load("//test/packetimpact/runner:defs.bzl", "packetimpact_go_test")

package(
    default_visibility = ["//test/packetimpact:__subpackages__"],
    licenses = ["notice"],
)

packetimpact_go_test(
    name = "fin_wait2_timeout",
    srcs = ["fin_wait2_timeout_test.go"],
    deps = [
        "//pkg/tcpip/header",
        "//test/packetimpact/testbench",
        "@org_golang_x_sys//unix:go_default_library",
    ],
)

packetimpact_go_test(
    name = "ipv4_id_uniqueness",
    srcs = ["ipv4_id_uniqueness_test.go"],
    # TODO(b/157506701) Fix netstack then remove the line below.
    expect_netstack_failure = True,
    deps = [
        "//pkg/abi/linux",
        "//pkg/tcpip/header",
        "//test/packetimpact/testbench",
        "@org_golang_x_sys//unix:go_default_library",
    ],
)

packetimpact_go_test(
    name = "udp_recv_multicast",
    srcs = ["udp_recv_multicast_test.go"],
    # TODO(b/152813495): Fix netstack then remove the line below.
    expect_netstack_failure = True,
    deps = [
        "//pkg/tcpip",
        "//pkg/tcpip/header",
        "//test/packetimpact/testbench",
        "@org_golang_x_sys//unix:go_default_library",
    ],
)

packetimpact_go_test(
    name = "udp_icmp_error_propagation",
    srcs = ["udp_icmp_error_propagation_test.go"],
    deps = [
        "//pkg/tcpip",
        "//pkg/tcpip/header",
        "//test/packetimpact/testbench",
        "@org_golang_x_sys//unix:go_default_library",
    ],
)

packetimpact_go_test(
    name = "tcp_reordering",
    srcs = ["tcp_reordering_test.go"],
    # TODO(b/139368047): Fix netstack then remove the line below.
    expect_netstack_failure = True,
    deps = [
        "//pkg/tcpip/header",
        "//pkg/tcpip/seqnum",
        "//test/packetimpact/testbench",
        "@org_golang_x_sys//unix:go_default_library",
    ],
)

packetimpact_go_test(
    name = "tcp_window_shrink",
    srcs = ["tcp_window_shrink_test.go"],
    deps = [
        "//pkg/tcpip/header",
        "//test/packetimpact/testbench",
        "@org_golang_x_sys//unix:go_default_library",
    ],
)

packetimpact_go_test(
    name = "tcp_zero_window_probe",
    srcs = ["tcp_zero_window_probe_test.go"],
    deps = [
        "//pkg/tcpip/header",
        "//test/packetimpact/testbench",
        "@org_golang_x_sys//unix:go_default_library",
    ],
)

packetimpact_go_test(
    name = "tcp_zero_window_probe_retransmit",
    srcs = ["tcp_zero_window_probe_retransmit_test.go"],
    deps = [
        "//pkg/tcpip/header",
        "//test/packetimpact/testbench",
        "@org_golang_x_sys//unix:go_default_library",
    ],
)

packetimpact_go_test(
    name = "tcp_zero_window_probe_usertimeout",
    srcs = ["tcp_zero_window_probe_usertimeout_test.go"],
    deps = [
        "//pkg/tcpip/header",
        "//test/packetimpact/testbench",
        "@org_golang_x_sys//unix:go_default_library",
    ],
)

packetimpact_go_test(
    name = "tcp_retransmits",
    srcs = ["tcp_retransmits_test.go"],
    deps = [
        "//pkg/tcpip/header",
        "//test/packetimpact/testbench",
        "@org_golang_x_sys//unix:go_default_library",
    ],
)

packetimpact_go_test(
    name = "tcp_outside_the_window",
    srcs = ["tcp_outside_the_window_test.go"],
    deps = [
        "//pkg/tcpip/header",
        "//pkg/tcpip/seqnum",
        "//test/packetimpact/testbench",
        "@org_golang_x_sys//unix:go_default_library",
    ],
)

packetimpact_go_test(
    name = "tcp_noaccept_close_rst",
    srcs = ["tcp_noaccept_close_rst_test.go"],
    deps = [
        "//pkg/tcpip/header",
        "//test/packetimpact/testbench",
        "@org_golang_x_sys//unix:go_default_library",
    ],
)

packetimpact_go_test(
    name = "tcp_send_window_sizes_piggyback",
    srcs = ["tcp_send_window_sizes_piggyback_test.go"],
    deps = [
        "//pkg/tcpip/header",
        "//test/packetimpact/testbench",
        "@org_golang_x_sys//unix:go_default_library",
    ],
)

packetimpact_go_test(
    name = "tcp_close_wait_ack",
    srcs = ["tcp_close_wait_ack_test.go"],
    deps = [
        "//pkg/tcpip/header",
        "//pkg/tcpip/seqnum",
        "//test/packetimpact/testbench",
        "@org_golang_x_sys//unix:go_default_library",
    ],
)

packetimpact_go_test(
    name = "tcp_paws_mechanism",
    srcs = ["tcp_paws_mechanism_test.go"],
    # TODO(b/156682000): Fix netstack then remove the line below.
    expect_netstack_failure = True,
    deps = [
        "//pkg/tcpip/header",
        "//pkg/tcpip/seqnum",
        "//test/packetimpact/testbench",
        "@org_golang_x_sys//unix:go_default_library",
    ],
)

packetimpact_go_test(
    name = "tcp_user_timeout",
    srcs = ["tcp_user_timeout_test.go"],
    deps = [
        "//pkg/tcpip/header",
        "//test/packetimpact/testbench",
        "@org_golang_x_sys//unix:go_default_library",
    ],
)

packetimpact_go_test(
    name = "tcp_queue_receive_in_syn_sent",
    srcs = ["tcp_queue_receive_in_syn_sent_test.go"],
    # TODO(b/157658105): Fix netstack then remove the line below.
    expect_netstack_failure = True,
    deps = [
        "//pkg/tcpip/header",
        "//test/packetimpact/testbench",
        "@org_golang_x_sys//unix:go_default_library",
    ],
)

packetimpact_go_test(
    name = "tcp_synsent_reset",
    srcs = ["tcp_synsent_reset_test.go"],
    deps = [
        "//pkg/tcpip/header",
        "//test/packetimpact/testbench",
        "@org_golang_x_sys//unix:go_default_library",
    ],
)

packetimpact_go_test(
    name = "tcp_synrcvd_reset",
    srcs = ["tcp_synrcvd_reset_test.go"],
    deps = [
        "//pkg/tcpip/header",
        "//test/packetimpact/testbench",
        "@org_golang_x_sys//unix:go_default_library",
    ],
)

packetimpact_go_test(
    name = "tcp_splitseg_mss",
    srcs = ["tcp_splitseg_mss_test.go"],
    deps = [
        "//pkg/tcpip/header",
        "//test/packetimpact/testbench",
        "@org_golang_x_sys//unix:go_default_library",
    ],
)

packetimpact_go_test(
    name = "tcp_cork_mss",
    srcs = ["tcp_cork_mss_test.go"],
    deps = [
        "//pkg/tcpip/header",
        "//test/packetimpact/testbench",
        "@org_golang_x_sys//unix:go_default_library",
    ],
)

packetimpact_go_test(
    name = "tcp_handshake_window_size",
    srcs = ["tcp_handshake_window_size_test.go"],
    deps = [
        "//pkg/tcpip/header",
        "//test/packetimpact/testbench",
        "@org_golang_x_sys//unix:go_default_library",
    ],
)

packetimpact_go_test(
    name = "icmpv6_param_problem",
    srcs = ["icmpv6_param_problem_test.go"],
    # TODO(b/153485026): Fix netstack then remove the line below.
    expect_netstack_failure = True,
    deps = [
        "//pkg/tcpip",
        "//pkg/tcpip/header",
        "//test/packetimpact/testbench",
        "@org_golang_x_sys//unix:go_default_library",
    ],
)

packetimpact_go_test(
    name = "ipv6_unknown_options_action",
    srcs = ["ipv6_unknown_options_action_test.go"],
    # TODO(b/159928940): Fix netstack then remove the line below.
    expect_netstack_failure = True,
    deps = [
        "//pkg/tcpip",
        "//pkg/tcpip/header",
        "//test/packetimpact/testbench",
        "@org_golang_x_sys//unix:go_default_library",
    ],
)

packetimpact_go_test(
    name = "udp_send_recv_dgram",
    srcs = ["udp_send_recv_dgram_test.go"],
    deps = [
        "//test/packetimpact/testbench",
        "@org_golang_x_sys//unix:go_default_library",
    ],
)
