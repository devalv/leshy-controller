#include <test_progs.h>

extern void
test_non_guarded_port(void);
extern void
test_guarded_port_no_auth(void);
extern void
test_active_flow_hit(void);
extern void
test_pending_promotion(void);
extern void
test_expired_pending_cleanup(void);
extern void
test_rst_generation(void);

void
test_rdp_filter(void)
{
    if (test__start_subtest("non_guarded_port"))
        test_non_guarded_port();
    if (test__start_subtest("guarded_port_no_auth"))
        test_guarded_port_no_auth();
    if (test__start_subtest("active_flow_hit"))
        test_active_flow_hit();
    if (test__start_subtest("pending_promotion"))
        test_pending_promotion();
    if (test__start_subtest("expired_pending_cleanup"))
        test_expired_pending_cleanup();
    if (test__start_subtest("rst_generation"))
        test_rst_generation();
}

int
main(int argc, char** argv)
{
    return test__run_suite("rdp_filter", test_rdp_filter);
}
