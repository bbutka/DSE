module feature_shell_with_mac_like (
    input  wire        clk,
    input  wire        rst_n,
    input  wire        valid_in,
    input  wire        write_in,
    input  wire [3:0]  src_id_in,
    input  wire [31:0] addr_in,
    input  wire [31:0] data_in,
    output wire        ready_out,
    output wire        valid_out,
    output wire        write_out,
    output wire [3:0]  src_id_out,
    output wire [31:0] addr_out,
    output wire [31:0] data_out,
    output wire        alarm_out
);

    feature_mac_like u_feature_mac_like (
        .clk(clk),
        .rst_n(rst_n),
        .valid_in(valid_in),
        .write_in(write_in),
        .src_id_in(src_id_in),
        .addr_in(addr_in),
        .data_in(data_in),
        .ready_out(ready_out),
        .valid_out(valid_out),
        .write_out(write_out),
        .src_id_out(src_id_out),
        .addr_out(addr_out),
        .data_out(data_out),
        .alarm_out(alarm_out)
    );

endmodule
