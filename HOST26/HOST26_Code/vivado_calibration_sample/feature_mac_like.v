module feature_mac_like (
    input  wire        clk,
    input  wire        rst_n,
    input  wire        valid_in,
    input  wire        write_in,
    input  wire [3:0]  src_id_in,
    input  wire [31:0] addr_in,
    input  wire [31:0] data_in,
    output wire        ready_out,
    output reg         valid_out,
    output reg         write_out,
    output reg  [3:0]  src_id_out,
    output reg  [31:0] addr_out,
    output reg  [31:0] data_out,
    output reg         alarm_out
);

    reg        valid_s1;
    reg        write_s1;
    reg [3:0]  src_id_s1;
    reg [31:0] addr_s1;
    reg [31:0] data_s1;
    reg [15:0] tag_s1;
    reg [15:0] tag_s2;
    reg [15:0] expected_tag;

    wire [15:0] mixed_addr;
    wire [15:0] mixed_data;
    wire [15:0] candidate_tag;
    wire        suspicious_addr;

    assign ready_out = 1'b1;
    assign mixed_addr = addr_in[31:16] ^ addr_in[15:0];
    assign mixed_data = data_in[31:16] ^ data_in[15:0];
    assign candidate_tag = mixed_addr ^ mixed_data ^ {11'd0, src_id_in, write_in};
    assign suspicious_addr = addr_s1[31:28] == 4'hF;

    always @(posedge clk) begin
        if (!rst_n) begin
            valid_s1     <= 1'b0;
            write_s1     <= 1'b0;
            src_id_s1    <= 4'd0;
            addr_s1      <= 32'd0;
            data_s1      <= 32'd0;
            tag_s1       <= 16'd0;
            tag_s2       <= 16'd0;
            expected_tag <= 16'hACE1;
            valid_out    <= 1'b0;
            write_out    <= 1'b0;
            src_id_out   <= 4'd0;
            addr_out     <= 32'd0;
            data_out     <= 32'd0;
            alarm_out    <= 1'b0;
        end else begin
            valid_s1  <= valid_in;
            write_s1  <= write_in;
            src_id_s1 <= src_id_in;
            addr_s1   <= addr_in;
            data_s1   <= data_in;
            tag_s1    <= candidate_tag;

            tag_s2    <= tag_s1 ^ expected_tag;

            valid_out  <= valid_s1;
            write_out  <= write_s1;
            src_id_out <= src_id_s1;
            addr_out   <= addr_s1;
            data_out   <= data_s1;

            alarm_out <= valid_s1 && (suspicious_addr || (tag_s2[3:0] == 4'h0));

            if (valid_s1) begin
                expected_tag <= {expected_tag[14:0], expected_tag[15]} ^ tag_s1;
            end
        end
    end

endmodule
