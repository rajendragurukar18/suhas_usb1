// ============================================================================
// usb_error_detect  --  USB 2.0 DEVICE packet receiver error detector
//                       (turn-around timeout with one input: rsp_expected;
//                        no tx_eop, no endpoint max-size input)
//
// Device side only. Hub-only mechanisms (EOF1/EOF2, frame timer, babble and
// loss-of-activity port disable) are not implemented: spec 8.7.4 makes hubs
// responsible for them (details in 11.8.1).
//
// FSM (per block diagram):
//   IDLE --pkt_start--> PID --(token|sof|data|handshake|invalid)--> TOKEN / SOF /
//   DATA / HS / DISCARD --pkt_end--> IDLE
//
//   * pkt_start in any state : restart in PID, per-packet flags cleared.
//   * pkt_end                : CRC / length / EOP-position checks, pkt_done.
//   * DATA packet with a bit-stuff error (stuff_error while in DATA) goes to
//     DISCARD at once; a DATA packet whose CRC16 is wrong (or that is too short
//     for PID+CRC16) goes to DISCARD at its EOP, stays there one clock and
//     returns to IDLE.  The data is discarded (Table 8-6/8-8); the flags are
//     still reported.  A stuff error in a TOKEN / SOF / handshake is only
//     flagged (the packet stays in its state).
//
// speed (input, sampled at pkt_start so a packet is judged at one speed):
//   2'd0 = Low Speed, 2'd1 = Full Speed, 2'd2 = High Speed, 2'd3 = treated as FS
//
// sync_error / stuff_error (from SIE/PHY):
//   sync_error high at pkt_start or while a packet is open -> packet goes to
//   (stays in) DISCARD: bytes counted, no PID/CRC/length check. sync_err set.
//
// ----------------------------------------------------------------------------
// Error definitions, with the USB 2.0 spec reference each one follows
//
//  Spec 8.7.1 / Table 8-6: with the exception of the SOF token, a corrupted
//  packet is ignored and its data/fields discarded.
//
//  pid_err     8.3.1: PID check field is not the complement of the PID, or the
//              PID decodes to a non-defined value -> packet ignored (DISCARD).
//              Treated as undefined at a device: reserved 0000, PRE/ERR (hub
//              PIDs; 8.6.5 "all other USB devices may ignore it and treat it
//              as undefined"), SPLIT (host<->hub only, 8.4.2), and the
//              HS-only PIDs (PING, NYET, DATA2, MDATA) when speed != HS.
//              Also set when EOP arrives before any PID byte (SOP then EOP):
//              no PID was received, so the packet is ignored (not defined
//              explicitly by the spec; mapped to the PID rule).
//              A valid PID that is not legal in the host-to-device direction
//              (NAK/STALL/NYET) is NOT an error here: 8.3.1 says the function
//              ignores it and does not respond (transaction-layer decision).
//
//  crc5_err    8.3.5.1: token / SOF CRC5 residual != 5'b01100.
//              For SOF the spec still treats the SOF PID as a valid SOF marker
//              (8.4.3, Table 8-6 "ignore Frame Number field"); only the frame
//              number must be ignored.
//  crc16_err   8.3.5.2: data CRC16 residual != 16'h800D.  Also set for a data
//              packet shorter than PID+CRC16 (3 bytes): 8.7.3 says a false EOP
//              makes a data packet "appear as a truncated packet with a CRC
//              failure".
//
//  len_err     Packet length outside what the spec allows (checked at pkt_end):
//                TOKEN : exactly 3 bytes                        (8.4.1)
//                HS    : exactly 1 byte                         (8.4.5)
//                DATA  : payload <= protocol maximum for the speed:
//                        LS 8 / FS 1023 / HS 1024               (8.4.4, ch.5)
//              The endpoint's own wMaxPacketSize (9.6.6) is NOT checked here;
//              that is a transaction-layer check.
//
//  eop_err     EOP not where the spec puts it (only spec-defined cases):
//                8.4.1: "Token and SOF packets are delimited by an EOP after
//                three bytes of packet field data. If a packet decodes as an
//                otherwise valid token or SOF but does not terminate with an
//                EOP after three bytes, it must be considered invalid and
//                ignored by the receiver."
//                8.4.5: "Handshake packets are delimited by an EOP after one
//                byte of packet field."  Same rule.
//              A false EOP inside a DATA packet is reported as crc16_err (8.7.3).
//              An EOP with no open packet is not a packet: ignored, no flags.
//
//  timeout_err 8.7.2 bus turn-around timeout (see also 7.1.18). The timer
//              starts at the EOP of the last RECEIVED packet and stops at the
//              next SOP. FS/LS: no sooner than 16, no later than 18 bit times
//              after the EOP; HS window 736-816 bit times (verify in the final
//              spec text). timeout_err + pkt_done are raised when the window
//              has expired and rsp_expected is set (rsp_expected may rise at
//              any time, also after the window). Reported once per EOP.
//              rsp_expected comes from the transaction layer (it alone knows
//              whether the token was for this device): hold it after an
//              OUT/SETUP token for this device until the host's data packet
//              starts.  NOT covered without tx_eop: the device's own packet
//              (IN data) is not received here, so the wait for the host ACK
//              cannot be timed by this block.
//
//  Clock-dependent parameters (defaults: 48 MHz clk for LS/FS, 60 MHz for HS),
//  chosen inside the spec window to leave margin for SIE latency:
//    TIMEOUT_LS : 17 LS bit times @ 32 clk/bit
//    TIMEOUT_FS : 17 FS bit times @  4 clk/bit
//    TIMEOUT_HS : 776 HS bit times @ 8 bit/clk
//
//  Not covered by this block:
//    * endpoint max packet size (9.6.6): transaction layer
//    * integral-byte-count check (8.3.4): the interface is byte based
//    * address / endpoint match (8.3.2): transaction layer
//    * device no-response rule on a corrupted packet: pkt_err -> no handshake
// ============================================================================
module usb_error_detect #(
    parameter TIMEOUT_LS = 544,    // 17 LS bit times @ 32 clk/bit
    parameter TIMEOUT_FS = 68,     // 17 FS bit times @  4 clk/bit
    parameter TIMEOUT_HS = 97      // 776 HS bit times @ 8 bit/clk
)(
    input  logic        clk,
    input  logic        rst_n,

    input  logic [1:0]  speed,        // 0=LS, 1=FS, 2=HS

    // SIE interface (pkt_end = EOP, SE0-to-J transition)
    input  logic        pkt_start,
    input  logic        pkt_end,
    input  logic        rx_valid,
    input  logic [7:0]  rx_byte,

    // Transaction layer: a packet is expected from the host. Hold from after
    // the EOP that requires it (OUT/SETUP token for this device) until that
    // packet's pkt_start. May rise any time before or after the window ends.
    input  logic        rsp_expected,

    // PHY/SIE error indications
    input  logic        sync_error,
    input  logic        stuff_error,

    // Error outputs
    output logic        sync_err,
    output logic        pid_err,
    output logic        crc5_err,
    output logic        crc16_err,
    output logic        stuff_err,
    output logic        eop_err,
    output logic        len_err,
    output logic        timeout_err,

    // Packet status
    output logic        pkt_err,
    output logic        pkt_done,
    output logic        pkt_valid
);

    // ------------------------------------------------
    // USB PID DEFINITIONS  ({~pid[3:0], pid[3:0]})
    // ------------------------------------------------
    localparam [7:0] PID_OUT   = 8'hE1;
    localparam [7:0] PID_IN    = 8'h69;
    localparam [7:0] PID_SOF   = 8'hA5;
    localparam [7:0] PID_SETUP = 8'h2D;
    localparam [7:0] PID_PING  = 8'hB4;   // HS only

    localparam [7:0] PID_DATA0 = 8'hC3;
    localparam [7:0] PID_DATA1 = 8'h4B;
    localparam [7:0] PID_DATA2 = 8'h87;   // HS only
    localparam [7:0] PID_MDATA = 8'h0F;   // HS only

    localparam [7:0] PID_ACK   = 8'hD2;
    localparam [7:0] PID_NAK   = 8'h5A;
    localparam [7:0] PID_STALL = 8'h1E;
    localparam [7:0] PID_NYET  = 8'h96;   // HS only

    localparam [1:0] SPD_LS = 2'd0;
    localparam [1:0] SPD_HS = 2'd2;

    localparam [15:0] T_LS = TIMEOUT_LS;
    localparam [15:0] T_FS = TIMEOUT_FS;
    localparam [15:0] T_HS = TIMEOUT_HS;

    localparam [11:0] TOKEN_BYTES = 12'd3;   // PID + 2 field bytes (CRC5 inside)
    localparam [11:0] HS_BYTES    = 12'd1;   // PID only (handshake)

    // ------------------------------------------------
    // FSM STATES
    // ------------------------------------------------
    typedef enum logic [2:0] {
        ST_IDLE    = 3'd0,
        ST_PID     = 3'd1,
        ST_TOKEN   = 3'd2,
        ST_DATA    = 3'd3,
        ST_HS      = 3'd4,
        ST_DISCARD = 3'd5,
        ST_SOF     = 3'd6
    } state_t;

    state_t state, state_nxt;
    state_t pid_class;
    state_t state_eff;      // state including the PID byte arriving this cycle

    // ------------------------------------------------
    // INTERNAL SIGNALS
    // ------------------------------------------------
    logic [1:0]  speed_q;               // speed latched at pkt_start
    logic        spd_hs, spd_ls;
    logic [11:0] proto_max;             // protocol payload maximum for the speed
    logic [11:0] max_data_bytes;

    logic [11:0] byte_count;
    logic [11:0] byte_count_inc;
    logic [11:0] byte_count_eff;

    logic [4:0]  crc5_reg,  crc5_next,  crc5_eff;
    logic [15:0] crc16_reg, crc16_next, crc16_eff;

    // CRC loop temporaries
    integer      i5, i16;
    logic [4:0]  c5;
    logic [15:0] c16;
    logic        fb5, fb16;

    logic in_pkt;
    logic rx_take;
    logic is_known_pid, is_hs_only, pid_comp_ok, pid_rsvd;
    logic sync_hit;         // sync_error while a packet is open -> discard
    logic stuff_hit;        // stuff_error while a DATA packet is open -> discard
    logic data_bad;         // DATA packet ends with wrong CRC16 / too short -> discard
    logic disc_tail;        // DISCARD entered at EOP: leave after one clock
    logic disc_tail_nxt;

    // bus turn-around timer
    logic        eop_evt;
    logic [15:0] ta_limit;
    logic [15:0] ta_cnt;
    logic        ta_run;
    logic        ta_expired;
    logic        to_done;
    logic        rsp_timeout_hit;

    assign in_pkt   = (state != ST_IDLE);
    assign rx_take  = rx_valid && in_pkt && !pkt_start;
    assign sync_hit = sync_error && in_pkt && !pkt_start;
    assign stuff_hit = stuff_error && (state == ST_DATA) && !pkt_start;

    // ------------------------------------------------
    // SPEED-DEPENDENT LIMITS
    // (packet speed while open, bus speed in IDLE)
    // ------------------------------------------------
    assign spd_hs = ((in_pkt ? speed_q : speed) == SPD_HS);
    assign spd_ls = ((in_pkt ? speed_q : speed) == SPD_LS);

    // Protocol payload maximum: LS 8, FS 1023, HS 1024 (spec 8.4.4)
    assign proto_max      = spd_ls ? 12'd8 : (spd_hs ? 12'd1024 : 12'd1023);
    assign max_data_bytes = proto_max + 12'd3;            // PID + payload + CRC16

    assign ta_limit = spd_ls ? T_LS : (spd_hs ? T_HS : T_FS);

    // ------------------------------------------------
    // BUS TURN-AROUND TIMER (spec 8.7.2)
    //   start : EOP of the previous received packet
    //   stop  : next SOP (pkt_start)
    //   expiry: ta_limit clk cycles after the EOP; reported as timeout_err
    //           when rsp_expected is set (it may rise any time before/after)
    // ------------------------------------------------
    assign eop_evt = pkt_end && (in_pkt || pkt_start);

    always_ff @(posedge clk or negedge rst_n) begin
        if (!rst_n) begin
            ta_run     <= 1'b0;
            ta_cnt     <= 16'd0;
            ta_expired <= 1'b0;
            to_done    <= 1'b0;
        end
        else if (eop_evt) begin
            ta_run     <= 1'b1;
            ta_cnt     <= 16'd0;
            ta_expired <= 1'b0;
            to_done    <= 1'b0;
        end
        else if (pkt_start) begin
            ta_run     <= 1'b0;
            ta_cnt     <= 16'd0;
            ta_expired <= 1'b0;
            to_done    <= 1'b0;
        end
        else begin
            if (ta_run && !ta_expired) begin
                if (ta_cnt == (ta_limit - 16'd1)) ta_expired <= 1'b1;
                else                              ta_cnt     <= ta_cnt + 16'd1;
            end
            if (rsp_timeout_hit)
                to_done <= 1'b1;
        end
    end

    assign rsp_timeout_hit = ta_run && ta_expired && rsp_expected && !to_done &&
                             !in_pkt && !pkt_start && !pkt_end;

    // ------------------------------------------------
    // CRC BYTE UPDATES
    // ------------------------------------------------
    // CRC5 : x^5 + x^2 + 1, 8 bits per byte, LSB first
    always_comb begin
        c5 = crc5_reg;
        for (i5 = 0; i5 < 8; i5 = i5 + 1) begin
            fb5 = c5[4] ^ rx_byte[i5];
            c5  = {c5[3:0], 1'b0};
            if (fb5) c5 = c5 ^ 5'h05;
        end
        crc5_next = c5;
    end

    // CRC16 : x^16 + x^15 + x^2 + 1, 8 bits per byte, LSB first
    always_comb begin
        c16 = crc16_reg;
        for (i16 = 0; i16 < 8; i16 = i16 + 1) begin
            fb16 = c16[15] ^ rx_byte[i16];
            c16  = {c16[14:0], 1'b0};
            if (fb16) c16 = c16 ^ 16'h8005;
        end
        crc16_next = c16;
    end

    // ------------------------------------------------
    // EFFECTIVE (INCLUDING CURRENT-CYCLE BYTE) VALUES
    // ------------------------------------------------
    assign byte_count_inc = (&byte_count) ? byte_count : (byte_count + 12'd1);
    assign byte_count_eff = rx_take ? byte_count_inc : byte_count;

    // ------------------------------------------------
    // PID DECODE -> PACKET CLASS (same cycle as the PID byte)
    // ------------------------------------------------
    assign pid_comp_ok = (rx_byte[7:4] == ~rx_byte[3:0]);
    assign pid_rsvd    = (rx_byte[3:0] == 4'b0000);   // reserved PID -> discard

    always_comb begin
        pid_class    = ST_DISCARD;
        is_known_pid = 1'b1;
        is_hs_only   = 1'b0;

        case (rx_byte)
            PID_OUT, PID_IN, PID_SETUP:  pid_class = ST_TOKEN;
            PID_SOF:                     pid_class = ST_SOF;
            PID_PING:                    begin pid_class = ST_TOKEN; is_hs_only = 1'b1; end
            PID_DATA0, PID_DATA1:        pid_class = ST_DATA;
            PID_DATA2, PID_MDATA:        begin pid_class = ST_DATA;  is_hs_only = 1'b1; end
            PID_ACK, PID_NAK, PID_STALL: pid_class = ST_HS;
            PID_NYET:                    begin pid_class = ST_HS;    is_hs_only = 1'b1; end
            default:                     is_known_pid = 1'b0;
        endcase

        if (is_hs_only && !spd_hs)
            is_known_pid = 1'b0;

        if (pid_rsvd)
            is_known_pid = 1'b0;

        if (!is_known_pid || !pid_comp_ok)
            pid_class = ST_DISCARD;
    end

    assign data_bad = (byte_count_eff < 12'd3) || (crc16_eff != 16'h800D);

    always_comb begin
        if (sync_hit || stuff_hit)           state_eff = ST_DISCARD;
        else if (state == ST_PID && rx_take) state_eff = pid_class;
        else                                 state_eff = state;
    end

    // ------------------------------------------------
    // FSM NEXT-STATE LOGIC
    // ------------------------------------------------
    always_comb begin
        state_nxt = state;

        if (pkt_start) begin
            // restart in PID; SOP immediately followed by EOP -> nothing to parse
            if (pkt_end)         state_nxt = ST_IDLE;
            else if (sync_error) state_nxt = ST_DISCARD;   // bad sync: do not receive
            else                 state_nxt = ST_PID;
        end
        else if (in_pkt) begin
            if (state == ST_DISCARD && disc_tail)
                state_nxt = ST_IDLE;                                 // end of the discard clock
            else if (pkt_end) begin
                if (state_eff == ST_DATA && data_bad)
                    state_nxt = ST_DISCARD;                          // data CRC error -> discard data
                else
                    state_nxt = ST_IDLE;
            end
            else if (sync_hit || stuff_hit)
                state_nxt = ST_DISCARD;                              // sync / data stuff error
            else if (state == ST_PID && rx_take)
                state_nxt = pid_class;
        end
    end

    assign disc_tail_nxt = in_pkt && !pkt_start && pkt_end &&
                           !(state == ST_DISCARD && disc_tail) &&
                           (state_eff == ST_DATA) && data_bad;

    always_ff @(posedge clk or negedge rst_n) begin
        if (!rst_n) begin
            state     <= ST_IDLE;
            disc_tail <= 1'b0;
        end
        else begin
            state     <= state_nxt;
            disc_tail <= disc_tail_nxt;
        end
    end

    // speed is captured once per packet
    always_ff @(posedge clk or negedge rst_n) begin
        if (!rst_n)         speed_q <= 2'd1;
        else if (pkt_start) speed_q <= speed;
    end

    // ------------------------------------------------
    // CRC NEXT-STATE (include current byte)
    // ------------------------------------------------
    always_comb begin
        crc5_eff  = crc5_reg;
        crc16_eff = crc16_reg;

        if (rx_take) begin
            // token: the two field bytes (byte_count 1 and 2) carry addr/endp + CRC5
            if ((state == ST_TOKEN || state == ST_SOF) &&
                (byte_count == 12'd1 || byte_count == 12'd2))
                crc5_eff = crc5_next;

            // data: payload + CRC16 (PID byte is consumed in ST_PID, not included)
            if (state == ST_DATA)
                crc16_eff = crc16_next;
        end
    end

    // ------------------------------------------------
    // DATAPATH / ERROR FLAGS
    // ------------------------------------------------
    always_ff @(posedge clk or negedge rst_n) begin
        if (!rst_n) begin
            byte_count  <= 12'd0;
            crc5_reg    <= 5'b11111;
            crc16_reg   <= 16'hFFFF;

            sync_err    <= 1'b0;
            pid_err     <= 1'b0;
            crc5_err    <= 1'b0;
            crc16_err   <= 1'b0;
            stuff_err   <= 1'b0;
            eop_err     <= 1'b0;
            len_err     <= 1'b0;
            timeout_err <= 1'b0;
            pkt_done    <= 1'b0;

        end
        else begin
            pkt_done <= 1'b0;

            // ========================================
            // pkt_start (any state): restart in PID, flags cleared
            // ========================================
            if (pkt_start) begin
                byte_count  <= 12'd0;
                crc5_reg    <= 5'b11111;
                crc16_reg   <= 16'hFFFF;

                sync_err    <= sync_error;
                stuff_err   <= stuff_error;

                crc5_err    <= 1'b0;
                crc16_err   <= 1'b0;
                eop_err     <= 1'b0;
                len_err     <= 1'b0;
                timeout_err <= 1'b0;

                // SOP immediately followed by EOP: no PID received -> ignored
                pid_err     <= pkt_end;
                pkt_done    <= pkt_end;

            end
            else begin

                // ------------------------------------
                // Bus-turnaround timeout (spec 8.7.2)
                // ------------------------------------
                if (rsp_timeout_hit) begin
                    sync_err    <= 1'b0;
                    stuff_err   <= 1'b0;
                    pid_err     <= 1'b0;
                    crc5_err    <= 1'b0;
                    crc16_err   <= 1'b0;
                    eop_err     <= 1'b0;
                    len_err     <= 1'b0;
                    timeout_err <= 1'b1;
                    pkt_done    <= 1'b1;
                end

                // ------------------------------------
                // While a packet is open: collect errors, count bytes
                // ------------------------------------
                if (in_pkt) begin
                    if (sync_error)  sync_err  <= 1'b1;
                    if (stuff_error) stuff_err <= 1'b1;

                    if (rx_take) begin
                        if (state == ST_PID && !sync_hit) begin
                            if (!(is_known_pid && pid_comp_ok))
                                pid_err <= 1'b1;        // undefined PID / bad check -> DISCARD
                        end
                        crc5_reg   <= crc5_eff;
                        crc16_reg  <= crc16_eff;
                        byte_count <= byte_count_inc;
                    end
                end

                // ------------------------------------
                // pkt_end: one branch per state.
                // state_eff = the state including a PID byte arriving this
                // cycle (and DISCARD if sync_error hit this cycle), so a last
                // byte on the same cycle as pkt_end is counted.
                // ------------------------------------
                if (pkt_end) begin
                    case (state_eff)

                        // EOP with no open packet is not a packet: ignored.
                        ST_IDLE: ;

                        // EOP before the PID byte: no PID received, packet ignored
                        ST_PID: begin
                            pid_err  <= 1'b1;
                            pkt_done <= 1'b1;
                        end

                        // Token/PING and SOF: EOP must follow exactly 3 bytes (8.4.1)
                        ST_TOKEN, ST_SOF: begin
                            pkt_done <= 1'b1;
                            if (byte_count_eff != TOKEN_BYTES) begin
                                eop_err <= 1'b1;
                                len_err <= 1'b1;
                            end
                            if (byte_count_eff >= TOKEN_BYTES &&
                                crc5_eff != 5'b01100)
                                crc5_err <= 1'b1;
                        end

                        // Data: false EOP shows up as truncated packet + CRC failure (8.7.3);
                        // a bad CRC16 also sends the FSM to DISCARD (see state_nxt)
                        ST_DATA: begin
                            pkt_done <= 1'b1;
                            if (byte_count_eff < 12'd3) begin
                                crc16_err <= 1'b1;      // no room for CRC16: truncated
                            end
                            else begin
                                if (crc16_eff != 16'h800D)
                                    crc16_err <= 1'b1;
                                if (byte_count_eff > max_data_bytes)
                                    len_err <= 1'b1;
                            end
                        end

                        // Handshake: EOP must follow exactly 1 byte (8.4.5)
                        ST_HS: begin
                            pkt_done <= 1'b1;
                            if (byte_count_eff != HS_BYTES) begin
                                eop_err <= 1'b1;
                                len_err <= 1'b1;
                            end
                        end

                        // undefined PID / sync error: counted only, no checks
                        ST_DISCARD: begin
                            pkt_done <= 1'b1;
                        end

                        default: ;
                    endcase
                end
            end
        end
    end

    // ------------------------------------------------
    // ERROR AGGREGATION
    // ------------------------------------------------
    assign pkt_err = sync_err | pid_err | crc5_err | crc16_err |
                     stuff_err | eop_err | len_err | timeout_err;

    assign pkt_valid = pkt_done && !pkt_err;

endmodule
