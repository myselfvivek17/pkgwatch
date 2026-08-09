//go:build !windows

package collect

import (
	"context"
	"fmt"
	"net"
)

// dialLocal opens the Docker socket. On everything but Windows that is an
// ordinary unix socket and the stdlib dialer is all it takes.
func dialLocal(ctx context.Context, network, address string) (net.Conn, error) {
	if network != "unix" {
		return nil, fmt.Errorf("collect: unsupported docker transport %q", network)
	}
	var dialer net.Dialer
	return dialer.DialContext(ctx, "unix", address)
}
