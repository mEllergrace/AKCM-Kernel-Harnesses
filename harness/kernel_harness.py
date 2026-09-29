#!/usr/bin/env python3
"""Real-kernel verification harness for AKCM's Linux security primitives.

Measures whether a kernel primitive (landlock, cgroup2, LSM stack, seccomp) is actually
present and what it reports, rather than citing a changelog or version number. That
distinction is why a mapping entry needs `kernel_version_min` AND `verification` fields:
a version bound with no measurement behind it is an assertion, not evidence.

Two independent backends emit the same KERNEL/PROBE/RESULT contract, parsed by the one
shared `parse_mechanism_probe`:

- `verify-mechanism` runs a disposable container on a REMOTE host's own kernel (via SSH),
  deliberately on the default runtime (not gVisor/runsc) since the whole point is measuring
  the real kernel, not a sandboxed reimplementation of one.
- The QEMU backend (`build_qemu_probe_script`) runs the same probe inside a disposable
  local VM whose kernel is actually selectable. This exists because capability is a
  build-configuration property, not a version property: measured directly, one Docker
  Desktop linuxkit kernel returned ENOSYS for landlock and exposed no LSM list at all,
  while a same-generation Ubuntu kernel reported landlock ABI 4 and five active LSMs. A
  `min_kernel` claim cannot be established from a single host for exactly this reason.

`runtime-status`/`install-gvisor` cover the separate question of container-host sandboxing
strength (AICM AIS-13): whether agent-generated code runs on plain runc or a hardened
runtime like gVisor, and installing the latter when it's missing.
"""
import argparse
import hashlib
import json
import os
import shlex
import shutil
import subprocess
import sys


def _ssh_prefix(vps, ssh_key):
    return ["ssh", "-i", ssh_key, "-o", "BatchMode=yes", vps]


# Mechanism probes for AKCM verification. Each MEASURES a kernel primitive rather than
# citing a document -- that distinction is the whole reason a mapping entry carries
# `kernel_version_min` and `verification` fields.
#
# These MUST run on the host's own kernel. A sandboxed runtime (e.g. gVisor) reimplements
# the kernel: inside one, `uname -r` reports a synthetic version, /proc/filesystems has no
# cgroup2, and /sys/kernel/security/lsm is absent. A probe run there measures the SANDBOX
# and returns a confident false negative for primitives the host fully supports.
KERNEL_PROBES = {
    # landlock_create_ruleset(NULL, 0, LANDLOCK_CREATE_RULESET_VERSION) returns the supported
    # ABI. There is no sysfs equivalent, so this is the only way to establish it -- and it
    # matters: network rules do not exist below ABI 4, so an entry claiming them is false on
    # such a kernel.
    "landlock-abi": (
        "python3 -c \""
        "import ctypes,platform;"
        "print('probe-unavailable-arch') if platform.machine() not in ('x86_64','aarch64') else "
        "print(ctypes.CDLL(None,use_errno=True).syscall(444,0,0,1))\" 2>/dev/null || echo probe-unavailable"
    ),
    "cgroup2": "grep -c cgroup2 /proc/filesystems 2>/dev/null || echo probe-unavailable",
    "lsm-list": "cat /sys/kernel/security/lsm 2>/dev/null || echo probe-unavailable",
    "seccomp-actions": "cat /proc/sys/kernel/seccomp/actions_avail 2>/dev/null || echo probe-unavailable",
}

MECHANISM_PROBE_PATHS = (
    "uname -r", "/proc/filesystems", "/sys/kernel/security/lsm",
    "/proc/sys/kernel/seccomp/actions_avail", "syscall landlock_create_ruleset(...VERSION)",
)


def build_mechanism_probe_argv(vps, ssh_key, image, probe):
    """Run one mechanism probe in a DISPOSABLE container on the host's real kernel.

    Deliberately does NOT pass --runtime: the host default (runc) shares the real kernel,
    which is the entire point. Passing runsc here would silently measure gVisor instead.
    """
    if probe not in KERNEL_PROBES:
        raise ValueError(
            f"unknown probe {probe!r}; known probes: {', '.join(sorted(KERNEL_PROBES))}"
        )
    body = (
        "echo KERNEL=$(uname -r); "
        "echo ARCH=$(uname -m); "
        f"echo PROBE={probe}; "
        f"echo RESULT=$({KERNEL_PROBES[probe]})"
    )
    remote = f"docker run --rm {image} sh -lc {shlex.quote(body)}"
    return _ssh_prefix(vps, ssh_key) + [remote]


def build_qemu_probe_script(runner_dir, probe, image, efi_code):
    """Run one mechanism probe inside a DISPOSABLE local QEMU VM on a REAL kernel.

    See the module docstring for why this backend exists alongside the remote-docker one.
    Emits the same KERNEL/PROBE/RESULT contract, so parse_mechanism_probe() is reused
    unchanged.
    """
    if probe not in KERNEL_PROBES:
        raise ValueError(
            f"unknown probe {probe!r}; known probes: {', '.join(sorted(KERNEL_PROBES))}"
        )
    # cloud-init runs the probe then powers off: unattended, no serial interaction, no SSH.
    user_data = (
        "#cloud-config\nruncmd:\n  - |\n"
        "    echo KERNEL=$(uname -r)\n"
        "    echo ARCH=$(uname -m)\n"
        f"    echo PROBE={probe}\n"
        f"    echo RESULT=$({KERNEL_PROBES[probe]})\n"
        "  - poweroff\n"
    )
    return {
        "user_data": user_data,
        # networking disabled: the probes need none, and systemd-networkd-wait-online
        # otherwise stalls the boot past any sane timeout.
        "meta_data": "instance-id: akcm-probe\nlocal-hostname: akcm-probe\nnetwork:\n  config: disabled\n",
        "argv": [
            "qemu-system-aarch64",
            "-machine", "virt,accel=hvf", "-cpu", "host", "-smp", "2", "-m", "2048",
            "-drive", f"if=pflash,format=raw,readonly=on,file={efi_code}",
            "-drive", f"if=pflash,format=raw,file={runner_dir}/efi-vars.fd",
            "-drive", f"if=virtio,format=qcow2,file={image}",
            "-drive", f"if=virtio,format=raw,file={runner_dir}/seed.iso",
            "-nographic", "-serial", "mon:stdio", "-display", "none",
        ],
    }


def build_qemu_run_spec(runner_dir, image, efi_code, user_data, instance_id):
    """Generic DISPOSABLE VM run: boot `image` with arbitrary cloud-init `user_data`.

    Unlike build_qemu_probe_script (kept as-is), this passes -snapshot so the base image is
    never written -- every run starts from the same bytes, which is what makes two runs
    comparable. The caller's user_data is responsible for printing its results to the
    serial console and powering off.
    """
    return {
        "user_data": user_data,
        "meta_data": f"instance-id: {instance_id}\nlocal-hostname: {instance_id}\nnetwork:\n  config: disabled\n",
        "argv": [
            "qemu-system-aarch64",
            "-machine", "virt,accel=hvf", "-cpu", "host", "-smp", "2", "-m", "2048",
            "-drive", f"if=pflash,format=raw,readonly=on,file={efi_code}",
            "-drive", f"if=pflash,format=raw,file={runner_dir}/efi-vars.fd",
            "-drive", f"if=virtio,format=qcow2,file={image}",
            "-drive", f"if=virtio,format=raw,file={runner_dir}/seed.iso",
            "-snapshot",
            "-nographic", "-serial", "mon:stdio", "-display", "none",
        ],
    }


def build_seed_iso_argv(seed_dir, iso_path, platform=None):
    """NoCloud seed: an ISO whose volume label is `cidata` holding user-data + meta-data."""
    platform = platform or sys.platform
    if platform == "darwin":
        return ["hdiutil", "makehybrid", "-o", iso_path, "-iso", "-joliet",
                "-default-volume-name", "cidata", seed_dir]
    return ["genisoimage", "-output", iso_path, "-volid", "cidata", "-joliet", "-rock", seed_dir]


def verify_sha256_line(sums_text, filename, digest):
    """True only if SHA256SUMS lists `filename` with exactly `digest`. A missing line is a
    refusal, not a pass -- an image we cannot check is not booted."""
    for line in (sums_text or "").splitlines():
        parts = line.split()
        if len(parts) == 2 and parts[1].lstrip("*") == filename:
            return parts[0].lower() == digest.lower()
    return False


def sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def run_qemu_vm(spec, runner_dir, vars_template, timeout=900, runner=subprocess.run, platform=None):
    """Write the seed ISO and a fresh EFI vars copy into runner_dir, boot, return serial text.

    The VM is expected to power itself off; `timeout` bounds a guest that never does.
    """
    seed_dir = os.path.join(runner_dir, "seed")
    os.makedirs(seed_dir, exist_ok=True)
    with open(os.path.join(seed_dir, "user-data"), "w") as f:
        f.write(spec["user_data"])
    with open(os.path.join(seed_dir, "meta-data"), "w") as f:
        f.write(spec["meta_data"])
    iso = os.path.join(runner_dir, "seed.iso")
    if os.path.exists(iso):
        os.remove(iso)
    proc = runner(build_seed_iso_argv(seed_dir, iso, platform), capture_output=True, text=True)
    if proc.returncode != 0:
        raise RuntimeError(f"seed ISO build failed: {proc.stderr.strip()}")
    shutil.copyfile(vars_template, os.path.join(runner_dir, "efi-vars.fd"))
    proc = runner(spec["argv"], capture_output=True, text=True, timeout=timeout,
                  stdin=subprocess.DEVNULL)
    return (proc.stdout or "") + (proc.stderr or "")


def parse_mechanism_probe(text):
    """Parse a probe result.

    `measured` distinguishes "the mechanism reported a value" from "the probe could not
    run". Conflating those is exactly how a false CANNOT verdict reaches a published
    mapping -- the absence of a tool is not the absence of a kernel feature.
    """
    fields = {}
    for line in (text or "").splitlines():
        if "=" in line:
            k, _, v = line.partition("=")
            fields[k.strip()] = v.strip()
    result = fields.get("RESULT", "")
    return {
        "kernel": fields.get("KERNEL", ""),
        # seccomp filters are arch-specific, so a result without its arch does not transfer.
        # Empty (not guessed) when the probe output predates the ARCH line.
        "arch": fields.get("ARCH", ""),
        "probe": fields.get("PROBE", ""),
        "result": result,
        "measured": bool(result) and not result.startswith("probe-unavailable"),
        "checked": list(MECHANISM_PROBE_PATHS),
    }


# gVisor ships supported builds for these only. Anything else is reported as "no
# published build found", never as "unsupported hardware".
GVISOR_ARCHES = ("x86_64", "amd64", "aarch64", "arm64")

RUNTIME_PROBE_PATHS = (
    "/etc/os-release", "uname -m", "uname -r", "command -v runsc", "/dev/kvm",
    "docker info --format '{{json .Runtimes}}'",
)


def build_runtime_probe_argv(vps, ssh_key):
    """READ-ONLY probe of the container host's sandboxing capability (AICM AIS-13).

    Agent-generated code commonly runs on runc. gVisor (`runsc`) is the realistic
    hardening step for a VPS: Kata needs nested virtualisation most VPS hosts do not
    expose, whereas gVisor's systrap platform runs in userspace and needs no /dev/kvm. We
    still report KVM because it selects a faster gVisor platform where present.

    Every command here only reads. Nothing installs, starts, or removes anything --
    deciding whether to change the host is the operator's call, and a probe that mutates
    cannot be run freely to find that out.
    """
    remote = "; ".join([
        "echo OS=$(. /etc/os-release 2>/dev/null && echo ${ID}-${VERSION_ID})",
        "echo ARCH=$(uname -m)",
        "echo KERNEL=$(uname -r)",
        "echo RUNSC=$(command -v runsc || echo none)",
        "echo KVM=$(test -e /dev/kvm && echo yes || echo no)",
        "echo RUNTIMES=$(docker info --format '{{json .Runtimes}}' 2>/dev/null || echo unavailable)",
        "echo DOCKERVER=$(docker version --format '{{.Server.Version}}' 2>/dev/null || echo unavailable)",
        # Existing daemon config must be MERGED into, never overwritten -- this host may
        # front live services and daemon.json may already carry log/registry/network settings.
        "echo DAEMONJSON=$(cat /etc/docker/daemon.json 2>/dev/null | tr -d '\\n' || echo absent)",
        # Restart policy decides what a daemon reload costs. Containers with a policy come
        # back by themselves; `no` ones stay stopped and someone must notice.
        "echo POLICIES=$(docker ps --format '{{.Names}}' 2>/dev/null | while read n; do echo -n \"$n=$(docker inspect -f '{{.HostConfig.RestartPolicy.Name}}' $n 2>/dev/null),\"; done)",
    ])
    return _ssh_prefix(vps, ssh_key) + [remote]


def parse_runtime_probe(text):
    """Parse the probe into a decision record.

    Reports what was FOUND and where it looked. It never states that a host cannot run
    something -- a probe observes absence at specific paths, which licenses a statement
    about those paths and nothing more.
    """
    fields = {}
    for line in (text or "").splitlines():
        if "=" in line:
            k, _, v = line.partition("=")
            fields[k.strip()] = v.strip()

    arch = fields.get("ARCH", "")
    runsc = fields.get("RUNSC", "none")
    raw_runtimes = fields.get("RUNTIMES", "unavailable")

    runtimes = None  # None means "could not read", which is NOT the same as "none configured"
    if raw_runtimes and raw_runtimes != "unavailable":
        try:
            runtimes = sorted(json.loads(raw_runtimes).keys())
        except (ValueError, AttributeError):
            runtimes = None

    supported = arch in GVISOR_ARCHES
    notes = []
    if not supported:
        notes.append(f"no published gVisor build found for arch {arch!r}")
    if runsc == "none":
        notes.append("runsc not found on PATH")
    if runtimes is None:
        notes.append("docker runtime list could not be read (docker absent, or not permitted)")
    if fields.get("KVM") == "no":
        notes.append("/dev/kvm absent -- gVisor systrap platform applies; Kata would not be an option here")

    policies = {}
    for pair in (fields.get("POLICIES", "") or "").split(","):
        if "=" in pair:
            name, _, pol = pair.partition("=")
            if name.strip():
                policies[name.strip()] = pol.strip() or "no"

    return {
        "docker_version": fields.get("DOCKERVER", ""),
        "restart_policies": policies,
        # A reload bounces containers; only those with a real policy return unattended.
        "would_not_restart": sorted(n for n, pol in policies.items() if pol in ("no", "")),
        "daemon_json": fields.get("DAEMONJSON", "absent"),
        "os": fields.get("OS", ""),
        "arch": arch,
        "kernel": fields.get("KERNEL", ""),
        "runsc_installed": runsc != "none",
        "runsc_path": None if runsc == "none" else runsc,
        "kvm": fields.get("KVM") == "yes",
        "runtimes": runtimes,
        "docker_knows_runsc": bool(runtimes) and "runsc" in runtimes,
        "gvisor_supported": supported,
        "notes": notes,
        "checked": list(RUNTIME_PROBE_PATHS),
    }


def host_runtime_status(vps, ssh_key, runner=subprocess.run, timeout=45):
    proc = runner(build_runtime_probe_argv(vps, ssh_key), capture_output=True, text=True, timeout=timeout)
    return parse_runtime_probe(proc.stdout or "")


GVISOR_RELEASE_URL = "https://storage.googleapis.com/gvisor/releases/release/latest"


def build_gvisor_install_argv(vps, ssh_key, allow_restart=False):
    """Install gVisor (runsc) and register it as a Docker runtime. MUTATES THE HOST.

    Closes AICM AIS-13: agent-generated code otherwise executes on runc, which shares the
    host kernel. gVisor interposes a userspace kernel, so a container escape has a second
    boundary to cross.

    Three deliberate safety properties, each pinned by a test:

    - **Checksum verification.** The binaries are fetched over the network and then run as
      root. An unverified download in that position is the whole attack.
    - **`runsc install` rather than hand-editing `/etc/docker/daemon.json`.** That file may
      already carry this host's log-driver configuration; the vendor's installer merges
      instead of overwriting. A backup is still taken first.
    - **Reload, not restart, by default.** `runtimes` is a SIGHUP-reloadable daemon option,
      so the runtime can be registered without bouncing every running container. A restart
      is available but must be asked for.
    """
    docker_apply = "systemctl restart docker" if allow_restart else "systemctl reload docker"
    remote = " && ".join([
        # Idempotent: a good install is not re-downloaded.
        'if command -v runsc >/dev/null 2>&1; then echo "runsc already installed: $(runsc --version | head -1)"; '
        f'else set -e; cd "$(mktemp -d)"; ARCH=$(uname -m); URL={GVISOR_RELEASE_URL}/${{ARCH}}; '
        'wget -q "${URL}/runsc" "${URL}/runsc.sha512" '
        '"${URL}/containerd-shim-runsc-v1" "${URL}/containerd-shim-runsc-v1.sha512"; '
        'sha512sum -c runsc.sha512 -c containerd-shim-runsc-v1.sha512; '
        'chmod a+rx runsc containerd-shim-runsc-v1; '
        'mv runsc containerd-shim-runsc-v1 /usr/local/bin/; fi',
        'cp -n /etc/docker/daemon.json /etc/docker/daemon.json.bak 2>/dev/null || true',
        '/usr/local/bin/runsc install',
        docker_apply,
        'sleep 2',
        "docker info --format '{{json .Runtimes}}'",
    ])
    return _ssh_prefix(vps, ssh_key) + [remote]


def build_arg_parser():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("action", choices=["verify-mechanism", "runtime-status", "install-gvisor"])
    parser.add_argument("--vps", required=True, help="e.g. root@203.0.113.10 -- no default; this host is yours, not ours")
    parser.add_argument("--ssh-key", required=True, help="path to the private key for --vps -- no default")
    parser.add_argument("--image", default="alpine:3", help="verify-mechanism only")
    parser.add_argument("--probe", help="verify-mechanism: one of " + ", ".join(sorted(KERNEL_PROBES)))
    parser.add_argument("--allow-restart", action="store_true",
                        help="install-gvisor: restart docker instead of reloading (bounces every container)")
    return parser


def main(argv=None):
    parser = build_arg_parser()
    args = parser.parse_args(argv)

    if args.action == "verify-mechanism":
        if not args.probe:
            print("--probe is required; known: " + ", ".join(sorted(KERNEL_PROBES)), file=sys.stderr)
            sys.exit(2)
        try:
            probe_argv = build_mechanism_probe_argv(args.vps, args.ssh_key, args.image, args.probe)
        except ValueError as e:
            print(f"REFUSED {e}", file=sys.stderr)
            sys.exit(2)
        proc = subprocess.run(probe_argv, capture_output=True, text=True, timeout=120)
        got = parse_mechanism_probe(proc.stdout or "")
        print(f"probe   : {got['probe']}")
        print(f"kernel  : {got['kernel'] or '-'}   <- the kernel this was MEASURED on")
        print(f"result  : {got['result'] or '-'}")
        print(f"measured: {got['measured']}"
              + ("" if got["measured"] else "   (probe could not run -- NOT a negative finding)"))
        print(f"checked : {', '.join(got['checked'])}")
        sys.exit(0 if got["measured"] else 1)
    elif args.action == "install-gvisor":
        install_argv = build_gvisor_install_argv(args.vps, args.ssh_key, allow_restart=args.allow_restart)
        proc = subprocess.run(install_argv, capture_output=True, text=True, timeout=600)
        print(proc.stdout.strip() or "(no stdout)")
        if proc.stderr.strip():
            print("stderr:", proc.stderr.strip(), file=sys.stderr)
        sys.exit(proc.returncode)
    elif args.action == "runtime-status":
        st = host_runtime_status(args.vps, args.ssh_key)
        print(f"host {args.vps}: os={st['os'] or '-'} arch={st['arch'] or '-'} kernel={st['kernel'] or '-'}")
        print(f"  runsc installed  : {st['runsc_installed']}{' at ' + st['runsc_path'] if st['runsc_path'] else ''}")
        print(f"  docker runtimes  : {', '.join(st['runtimes']) if st['runtimes'] else 'could not read'}")
        print(f"  docker has runsc : {st['docker_knows_runsc']}")
        print(f"  gvisor build available for this arch: {st['gvisor_supported']}")
        print(f"  docker version   : {st['docker_version'] or '-'}")
        print(f"  /etc/docker/daemon.json: {st['daemon_json'] or 'absent'}")
        if st["restart_policies"]:
            print(f"  running containers ({len(st['restart_policies'])}): "
                  + ", ".join(f"{n}={p}" for n, p in sorted(st["restart_policies"].items())))
            if st["would_not_restart"]:
                print(f"  WOULD NOT COME BACK after a daemon restart: {', '.join(st['would_not_restart'])}")
        for n in st["notes"]:
            print(f"  note: {n}")
        print(f"  checked: {', '.join(st['checked'])}")
        sys.exit(0 if st["docker_knows_runsc"] else 1)


if __name__ == "__main__":
    main()
