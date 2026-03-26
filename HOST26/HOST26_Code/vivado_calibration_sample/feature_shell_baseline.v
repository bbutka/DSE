module feature_shell_baseline (
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
    output wire        alarm_out
);

    assign ready_out = 1'b1;
    assign alarm_out = 1'b0;

    always @(posedge clk) begin
        if (!rst_n) begin
            valid_out  <= 1'b0;
            write_out  <= 1'b0;
            src_id_out <= 4'd0;
            addr_out   <= 32'd0;
            data_out   <= 32'd0;
        end else begin
            valid_out  <= valid_in;
            write_out  <= write_in;
            src_id_out <= src_id_in;
            addr_out   <= addr_in;
            data_out   <= data_in;
        end
    end

endmodule
