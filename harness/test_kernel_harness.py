"""Tests for kernel_harness.py -- ported, unmodified in behavior, from the four test
classes that actually exercise the kernel-primitive verification surface (runtime
capability probing, gVisor install, mechanism probing, and the QEMU backend). Run:
python3 -m pytest harness/test_kernel_harness.py -q
"""
import unittest

from kernel_harness import (
    build_qemu_probe_script,
    build_mechanism_probe_argv,
    parse_mechanism_probe,
    build_gvisor_install_argv,
    build_runtime_probe_argv,
    parse_runtime_probe,
    build_qemu_run_spec,
    build_seed_iso_argv,
    verify_sha256_line,
    run_qemu_vm,
)


class TestRuntimeProbe(unittest.TestCase):
    """Read-only probe of the container HOST's sandboxing capability (AICM AIS-13).

    Agent-generated code currently executes on runc. gVisor (runsc) is the realistic
    hardening step on a VPS: Kata needs nested virtualisation most VPS hosts do not expose,
    while gVisor's systrap platform runs in userspace and does not require /dev/kvm.

    The probe is READ-ONLY by construction and must never claim a host "cannot" do something --
    it reports what was found and WHERE IT LOOKED, per the negative-findings rule.
    """

    def test_probe_argv_is_read_only(self):
        argv = build_runtime_probe_argv("root@h", "/k")
        remote = argv[-1]
        for mutator in ("docker run", "apt-get", "install", "rm ", "systemctl", "curl", "wget", "tee "):
            self.assertNotIn(mutator, remote, f"probe must not mutate the host: found {mutator!r}")
        self.assertNotIn(">", remote.replace("2>/dev/null", ""),
                         "probe must not redirect output onto the host filesystem")

    def test_probe_collects_the_fields_a_runtime_decision_needs(self):
        remote = build_runtime_probe_argv("root@h", "/k")[-1]
        for field in ("ARCH", "KERNEL", "RUNSC", "KVM", "RUNTIMES"):
            self.assertIn(field, remote)

    def test_parses_a_host_with_no_hardened_runtime(self):
        got = parse_runtime_probe(
            "OS=ubuntu-22.04\nARCH=x86_64\nKERNEL=5.15.0-88-generic\n"
            "RUNSC=none\nKVM=no\nRUNTIMES={\"runc\":{\"path\":\"runc\"}}\n"
        )
        self.assertEqual(got["arch"], "x86_64")
        self.assertFalse(got["runsc_installed"])
        self.assertEqual(got["runtimes"], ["runc"])
        self.assertTrue(got["gvisor_supported"], "x86_64 linux supports gVisor systrap without KVM")

    def test_parses_a_host_that_already_has_runsc(self):
        got = parse_runtime_probe(
            "OS=debian-12\nARCH=aarch64\nKERNEL=6.1.0\nRUNSC=/usr/local/bin/runsc\nKVM=yes\n"
            "RUNTIMES={\"runc\":{\"path\":\"runc\"},\"runsc\":{\"path\":\"/usr/local/bin/runsc\"}}\n"
        )
        self.assertTrue(got["runsc_installed"])
        self.assertIn("runsc", got["runtimes"])
        self.assertTrue(got["docker_knows_runsc"])

    def test_unsupported_arch_is_reported_without_claiming_impossible(self):
        got = parse_runtime_probe("OS=x\nARCH=riscv64\nKERNEL=6.1\nRUNSC=none\nKVM=no\nRUNTIMES=unavailable\n")
        self.assertFalse(got["gvisor_supported"])
        blob = " ".join(got["notes"]).lower()
        for forbidden in ("cannot", "incapable", "impossible", "never"):
            self.assertNotIn(forbidden, blob, "a negative must describe what was found, not assert incapability")

    def test_reports_where_it_looked(self):
        got = parse_runtime_probe("OS=x\nARCH=x86_64\nKERNEL=6.1\nRUNSC=none\nKVM=no\nRUNTIMES=unavailable\n")
        self.assertTrue(got["checked"], "a negative finding must carry its search path")

    def test_docker_unavailable_is_not_read_as_no_runtimes(self):
        got = parse_runtime_probe("OS=x\nARCH=x86_64\nKERNEL=6.1\nRUNSC=none\nKVM=no\nRUNTIMES=unavailable\n")
        self.assertIsNone(got["runtimes"], "unavailable must stay distinct from an empty list")


class TestGvisorInstall(unittest.TestCase):
    """Installing a hardened runtime (AICM AIS-13).

    Any host running this may already front live services and hold long-running
    containers. The install must therefore be additive and reversible-ish: verify what
    it downloads, back up daemon config before touching it, and prefer a daemon RELOAD
    over a restart so running containers are not bounced.
    """

    def test_downloaded_binaries_are_checksum_verified(self):
        remote = build_gvisor_install_argv("root@h", "/k")[-1]
        self.assertIn("sha512", remote,
                      "a binary fetched over the network must be verified before it is run as root")

    def test_daemon_json_is_backed_up_before_modification(self):
        remote = build_gvisor_install_argv("root@h", "/k")[-1]
        self.assertIn("daemon.json.bak", remote,
                      "existing daemon config (log-driver settings here) must be recoverable")

    def test_uses_runsc_install_rather_than_hand_editing_daemon_json(self):
        remote = build_gvisor_install_argv("root@h", "/k")[-1]
        self.assertIn("runsc install", remote)

    def test_reloads_rather_than_restarts_docker_by_default(self):
        remote = build_gvisor_install_argv("root@h", "/k")[-1]
        self.assertIn("reload", remote)
        self.assertNotIn("systemctl restart docker", remote,
                         "a restart bounces every container on the host; reload does not")

    def test_restart_is_possible_but_opt_in(self):
        remote = build_gvisor_install_argv("root@h", "/k", allow_restart=True)[-1]
        self.assertIn("restart docker", remote)

    def test_is_idempotent_when_runsc_already_present(self):
        remote = build_gvisor_install_argv("root@h", "/k")[-1]
        self.assertIn("command -v runsc", remote,
                      "re-running the installer must not re-download over a good install")


class TestMechanismProbe(unittest.TestCase):
    """The real-kernel verification runner (AKCM gaps 3/4).

    Sandboxed runtimes (e.g. gVisor) reimplement the kernel: inside one, `uname -r`
    reports a synthetic version, /proc/filesystems has no cgroup2, and
    /sys/kernel/security/lsm is absent. A mechanism probe run there measures the SANDBOX
    and returns a false negative for primitives the host fully supports. So verification
    MUST run on the host's own kernel.
    """

    def test_probe_does_not_use_the_gvisor_runtime(self):
        argv = build_mechanism_probe_argv("root@h", "/k", "alpine:3", "landlock-abi")
        self.assertNotIn("runsc", argv[-1])

    def test_probe_container_is_disposable(self):
        argv = build_mechanism_probe_argv("root@h", "/k", "alpine:3", "landlock-abi")
        self.assertIn("--rm", argv[-1], "a verification run must not leave a container behind")

    def test_probe_reports_the_kernel_it_measured_on(self):
        argv = build_mechanism_probe_argv("root@h", "/k", "alpine:3", "landlock-abi")
        self.assertIn("uname -r", argv[-1])

    def test_unknown_probe_name_is_refused(self):
        with self.assertRaises(ValueError) as ctx:
            build_mechanism_probe_argv("root@h", "/k", "alpine:3", "no-such-probe")
        self.assertIn("no-such-probe", str(ctx.exception))

    def test_parses_a_measured_result(self):
        got = parse_mechanism_probe("KERNEL=6.8.0-134-generic\nPROBE=landlock-abi\nRESULT=4\n")
        self.assertEqual(got["kernel"], "6.8.0-134-generic")
        self.assertEqual(got["probe"], "landlock-abi")
        self.assertEqual(got["result"], "4")
        self.assertTrue(got["measured"])

    def test_a_probe_that_could_not_run_is_not_reported_as_a_negative_result(self):
        got = parse_mechanism_probe("KERNEL=6.8.0-134-generic\nPROBE=landlock-abi\nRESULT=probe-unavailable\n")
        self.assertFalse(got["measured"])
        self.assertIn("probe-unavailable", got["result"])

    def test_result_carries_the_search_path(self):
        got = parse_mechanism_probe("KERNEL=6.8\nPROBE=cgroup2\nRESULT=0\n")
        self.assertTrue(got["checked"], "a negative must say where it looked")


class TestQemuProbeBackend(unittest.TestCase):
    """The QEMU backend exists because a container measures ONE kernel's build config.

    Measured directly: one Docker Desktop linuxkit kernel returned ENOSYS for landlock and
    exposed no LSM list, while a same-generation Ubuntu kernel reported landlock ABI 4 and
    five LSM modules. The LOWER version had MORE capability -- capability is a
    build-configuration property, not a version property. A `min_kernel` claim therefore
    cannot come from a single host; a VM whose kernel is selectable is required.
    """

    def test_emits_the_same_contract_the_docker_path_does(self):
        spec = build_qemu_probe_script("/r", "landlock-abi", "/r/img.qcow2", "/fw/code.fd")
        self.assertIn("echo KERNEL=$(uname -r)", spec["user_data"])
        self.assertIn("echo PROBE=landlock-abi", spec["user_data"])
        self.assertIn("echo RESULT=$(", spec["user_data"])
        got = parse_mechanism_probe("KERNEL=6.8.0-136-generic\nPROBE=landlock-abi\nRESULT=4")
        self.assertEqual(got["probe"], "landlock-abi")

    def test_powers_off_so_the_vm_is_actually_disposable(self):
        spec = build_qemu_probe_script("/r", "cgroup2", "/r/img.qcow2", "/fw/code.fd")
        self.assertIn("poweroff", spec["user_data"])

    def test_networking_disabled_or_the_boot_stalls(self):
        spec = build_qemu_probe_script("/r", "cgroup2", "/r/img.qcow2", "/fw/code.fd")
        self.assertIn("network:\n  config: disabled", spec["meta_data"])

    def test_unknown_probe_is_refused_not_guessed(self):
        with self.assertRaises(ValueError):
            build_qemu_probe_script("/r", "not-a-probe", "/r/img.qcow2", "/fw/code.fd")

    def test_uses_hvf_and_never_a_sandboxed_runtime(self):
        spec = build_qemu_probe_script("/r", "lsm-list", "/r/img.qcow2", "/fw/code.fd")
        argv = " ".join(spec["argv"])
        self.assertIn("accel=hvf", argv)
        self.assertNotIn("runsc", argv)


class TestQemuRunBackend(unittest.TestCase):
    """Generic disposable-VM launch: the probe builder above only ever built a spec, nothing
    launched it. These pin the properties that make a VM run count as evidence: the base
    image is never written (-snapshot), the guest's own uname is what gets reported, and a
    downloaded image is checksum-verified before it is booted."""

    def test_run_spec_is_disposable_and_carries_the_given_user_data(self):
        spec = build_qemu_run_spec("/r", "/r/base.img", "/fw/code.fd", "#cloud-config\n", "akcm-x")
        self.assertIn("-snapshot", spec["argv"])
        self.assertEqual(spec["user_data"], "#cloud-config\n")
        self.assertIn("instance-id: akcm-x", spec["meta_data"])
        self.assertIn("network:\n  config: disabled", spec["meta_data"])
        self.assertIn("accel=hvf", " ".join(spec["argv"]))

    def test_probe_builder_output_is_unchanged_by_the_generic_path(self):
        spec = build_qemu_probe_script("/r", "cgroup2", "/r/img.qcow2", "/fw/code.fd")
        self.assertNotIn("-snapshot", spec["argv"])
        self.assertIn("instance-id: akcm-probe", spec["meta_data"])

    def test_probe_contract_now_records_architecture(self):
        spec = build_qemu_probe_script("/r", "cgroup2", "/r/img.qcow2", "/fw/code.fd")
        self.assertIn("echo ARCH=$(uname -m)", spec["user_data"])
        got = parse_mechanism_probe("KERNEL=6.8.0-1-generic\nARCH=aarch64\nPROBE=cgroup2\nRESULT=1")
        self.assertEqual(got["arch"], "aarch64")
        self.assertEqual(parse_mechanism_probe("KERNEL=k\nPROBE=p\nRESULT=1")["arch"], "")

    def test_seed_iso_is_labelled_cidata_for_nocloud(self):
        argv = build_seed_iso_argv("/r/seed", "/r/seed.iso", platform="darwin")
        self.assertEqual(argv[0], "hdiutil")
        self.assertIn("cidata", argv)
        argv = build_seed_iso_argv("/r/seed", "/r/seed.iso", platform="linux")
        self.assertIn("cidata", argv)

    def test_checksum_mismatch_is_refused(self):
        sums = "abc123 *noble.img\nfff *other.img\n"
        self.assertTrue(verify_sha256_line(sums, "noble.img", "abc123"))
        self.assertFalse(verify_sha256_line(sums, "noble.img", "999"))
        self.assertFalse(verify_sha256_line(sums, "missing.img", "abc123"))

    def test_run_writes_seed_then_boots_and_returns_serial_output(self):
        import tempfile
        calls = []

        class P:
            def __init__(self, out):
                self.stdout, self.stderr, self.returncode = out, "", 0

        def fake(argv, **kw):
            calls.append(argv[0])
            return P("boot\nAKCM-OUT\n" if argv[0].startswith("qemu") else "")

        with tempfile.TemporaryDirectory() as d:
            import os
            vars_src = os.path.join(d, "vars.fd")
            open(vars_src, "wb").write(b"\0" * 16)
            spec = build_qemu_run_spec(d, "/base.img", "/code.fd", "#cloud-config\n", "t")
            out = run_qemu_vm(spec, d, vars_template=vars_src, timeout=5, runner=fake, platform="darwin")
            self.assertTrue(os.path.exists(os.path.join(d, "seed", "user-data")))
            self.assertTrue(os.path.exists(os.path.join(d, "efi-vars.fd")))
        self.assertEqual(calls, ["hdiutil", "qemu-system-aarch64"])
        self.assertIn("AKCM-OUT", out)


class TestCliSurface(unittest.TestCase):
    """This harness ships exactly 3 verbs -- proof the trim from the source tool (which
    also covered container provisioning/teardown/OAuth-login plumbing unrelated to kernel
    verification) was intentional and complete, not partial."""

    def test_kept_verbs_present_and_dropped_verbs_absent(self):
        import kernel_harness

        parser = kernel_harness.build_arg_parser()
        action_choices = None
        for action in parser._actions:
            if action.dest == "action":
                action_choices = set(action.choices)
        self.assertEqual(action_choices, {"verify-mechanism", "runtime-status", "install-gvisor"})


if __name__ == "__main__":
    unittest.main()
