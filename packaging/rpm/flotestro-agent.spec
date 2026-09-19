Name:           flotestro-agent
Version:        %{?_flotestro_version}%{!?_flotestro_version:0.1.0}
Release:        1%{?dist}
Summary:        Flotestro fleet agent
License:        Proprietary
URL:            https://github.com/ultherego/flotestro
BuildArch:      %{_target_cpu}

# The runtime dependencies are the whole of what the agent needs: systemd
# for the units and the journal, the trust store for the session to the
# control plane, and the shadow tools the local account module mutates
# accounts with. No module pulls a backend of its own in - a tool that is
# not on the host disables exactly one capability, which the agent reports
# as unavailable together with the name of the package that restores it.
Requires:       systemd
Requires:       ca-certificates
Requires:       shadow-utils
Requires(post): systemd, shadow-utils
Requires(preun): systemd
# A weak dependency dnf does not install by itself: without the versionlock
# plugin the host simply reports packages.hold as a feature it has not got.
Suggests:       python3-dnf-plugin-versionlock

# The binaries are built earlier and given by directory; the spec compiles
# no code, so that the package is made from exactly the same artefacts that
# passed the tests.
%global _build_id_links none
%global __strip /bin/true

%description
The agent connects a host to the Linux fleet management panel. It keeps an
mTLS session to the control plane, reports the inventory and carries out
only typed operations - the contract has no field for an arbitrary shell
command.

Operations that require root are carried out by a separate helper process
started by a systemd socket, which verifies the caller by SO_PEERCRED. The
agent itself runs without root privileges.

%install
rm -rf %{buildroot}
install -d -m 0755 %{buildroot}%{_bindir}
install -m 0755 %{_flotestro_stage}/flotestro-agent        %{buildroot}%{_bindir}/flotestro-agent
install -m 0755 %{_flotestro_stage}/flotestro-agent-helper %{buildroot}%{_bindir}/flotestro-agent-helper
install -m 0755 %{_flotestro_stage}/flotestro-agentctl     %{buildroot}%{_bindir}/flotestro-agentctl

install -d -m 0755 %{buildroot}%{_unitdir}
install -m 0644 %{_flotestro_units}/flotestro-agent.service  %{buildroot}%{_unitdir}/
install -m 0644 %{_flotestro_units}/flotestro-enroll.service %{buildroot}%{_unitdir}/
install -m 0644 %{_flotestro_units}/flotestro-helper.service %{buildroot}%{_unitdir}/
install -m 0644 %{_flotestro_units}/flotestro-helper.socket  %{buildroot}%{_unitdir}/

install -d -m 0755 %{buildroot}%{_sysconfdir}/flotestro
install -m 0640 %{_flotestro_stage}/agent.yaml %{buildroot}%{_sysconfdir}/flotestro/agent.yaml
install -m 0640 %{_flotestro_stage}/agent.env  %{buildroot}%{_sysconfdir}/flotestro/agent.env

install -d -m 0700 %{buildroot}%{_sharedstatedir}/flotestro-agent
# The bill of materials of the binaries: written when they were built,
# read from the build metadata they carry. A stage without it makes a
# package without it; the release checklist notices, not this file.
install -d -m 0755 %{buildroot}%{_docdir}/flotestro-agent
[ -f %{_flotestro_stage}/sbom/flotestro-agent.cdx.json ] && \
    install -m 0644 %{_flotestro_stage}/sbom/flotestro-agent.cdx.json %{buildroot}%{_docdir}/flotestro-agent/sbom.cdx.json || :
[ -f %{_flotestro_stage}/sbom/flotestro-agent-helper.cdx.json ] && \
    install -m 0644 %{_flotestro_stage}/sbom/flotestro-agent-helper.cdx.json %{buildroot}%{_docdir}/flotestro-agent/sbom-flotestro-agent-helper.cdx.json || :
[ -f %{_flotestro_stage}/sbom/flotestro-agentctl.cdx.json ] && \
    install -m 0644 %{_flotestro_stage}/sbom/flotestro-agentctl.cdx.json %{buildroot}%{_docdir}/flotestro-agent/sbom-flotestro-agentctl.cdx.json || :

%files
%{_docdir}/flotestro-agent
%{_bindir}/flotestro-agent
%{_bindir}/flotestro-agent-helper
%{_bindir}/flotestro-agentctl
%{_unitdir}/flotestro-agent.service
%{_unitdir}/flotestro-enroll.service
%{_unitdir}/flotestro-helper.service
%{_unitdir}/flotestro-helper.socket
%dir %{_sysconfdir}/flotestro
# The configuration must not be overwritten on an update: it holds the
# panel address and the enrollment token of this host.
%config(noreplace) %attr(0640, root, flotestro-agent) %{_sysconfdir}/flotestro/agent.yaml
%config(noreplace) %attr(0640, root, flotestro-agent) %{_sysconfdir}/flotestro/agent.env
%dir %attr(0700, flotestro-agent, flotestro-agent) %{_sharedstatedir}/flotestro-agent

%pre
# A service account without a shell and without a home directory: the agent
# is not an identity anybody logs into the host with.
getent group flotestro-agent >/dev/null || groupadd --system flotestro-agent
getent passwd flotestro-agent >/dev/null || \
    useradd --system --gid flotestro-agent --no-create-home \
        --home-dir %{_sharedstatedir}/flotestro-agent --shell /sbin/nologin \
        flotestro-agent
exit 0

%post
# Reading the journal without root requires membership in the systemd-journal
# group. A missing group is not an installation error - the journal read is
# then unavailable, and the agent reports that instead of pretending the
# journal is empty.
if getent group systemd-journal >/dev/null; then
    usermod --append --groups systemd-journal flotestro-agent || :
fi
# The daemon no longer enrolls, so a token left in the environment file from
# the old flow is a secret lying in a file that survives updates and ends up
# in backups. The package says so and touches nothing: the file is the
# operator's, and the token is usually spent anyway.
if [ -f %{_sysconfdir}/flotestro/agent.env ] &&
   grep -Eq '^[[:space:]]*FLOTESTRO_ENROLLMENT_TOKEN=[[:space:]]*[^[:space:]#]' %{_sysconfdir}/flotestro/agent.env; then
    echo "flotestro-agent: %{_sysconfdir}/flotestro/agent.env still carries FLOTESTRO_ENROLLMENT_TOKEN" >&2
    echo "  the daemon ignores it; enrollment is done with: sudo -u flotestro-agent flotestro-agentctl enroll" >&2
    echo "  remove the line from the file" >&2
fi
%systemd_post flotestro-agent.service flotestro-helper.socket
# The helper socket must exist before the agent tries to connect to it.
systemctl enable --now flotestro-helper.socket || :
# The helper keeps running after the binary is replaced, so after an update
# it would serve jobs with the old code. The socket starts the new version at
# the next job.
systemctl stop flotestro-helper.service || :

# An agent without a panel address has nowhere to connect. Running it in a
# restart loop would litter the host journal; the installation then ends
# with a hint, not a quiet error.
systemctl enable flotestro-agent.service || :
if [ -e %{_sharedstatedir}/flotestro-agent/identity/current/agent.pem ] ||
   [ -e %{_sharedstatedir}/flotestro-agent/agent.pem ]; then
    systemctl start flotestro-agent.service || :
else
    echo "flotestro-agent: fill in %{_sysconfdir}/flotestro/agent.yaml and enroll the host" >&2
    echo "  sudo -u flotestro-agent flotestro-agentctl enroll" >&2
    echo "  systemctl start flotestro-agent.service" >&2
fi

%preun
%systemd_preun flotestro-agent.service flotestro-helper.socket

%postun
%systemd_postun_with_restart flotestro-agent.service
# The agent identity and the private key stay on an update and on an
# ordinary removal: a reinstall is to recover the same identity without
# enrollment.

%changelog
