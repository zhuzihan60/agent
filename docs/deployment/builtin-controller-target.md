# Built-in controller and target deployment

Install the signed controller archive on the controller host and verify its
signature and `SHA256SUMS`. Generate a reviewed `target-install.json` with
`a4diag target bootstrap`, then transfer and install the signed target archive
on the target host. Target installation is a human action and is never
performed by the Agent.

Register the target in settings v3 in read-only mode first. Confirm the pinned
machine-id, OS, systemd, and SSH host-key identity. Enable LOW execution only
after the target policy and managed roots are reviewed. HIGH operations remain
pending until `a4diag approvals show`, `approve`, and an explicit
`a4diag resume TRANSACTION` (or equivalent service trigger).

Every operation has typed verification and undo. Audit and report stores are
append-only and survive restart. SSH, network, firewall, key, user, kernel,
libvirt, and VM-lifecycle resources remain permanently blocked, including when
an approval is present.
