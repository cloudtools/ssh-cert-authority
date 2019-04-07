// copied from https://gist.github.com/svett/5d695dcc4cc6ad5dd275

package ssh_ca_util

import (
//	"log"
//	"bufio"
//	"time"
	"os"
	"fmt"
	"io"
	"strings"
	"strconv"
	"net"
	"net/url"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

type Endpoint struct {
	Host string
	Port int
}

func (endpoint *Endpoint) String() string {
	return fmt.Sprintf("%s:%d", endpoint.Host, endpoint.Port)
}

type SSHtunnel struct {
	Local  *Endpoint
	Server *Endpoint
	Remote *Endpoint

	Config *ssh.ClientConfig
}

func (tunnel *SSHtunnel) Start() error {
	listener, err := net.Listen("tcp", tunnel.Local.String())
	if err != nil {
		return err
	}
	defer listener.Close()

	for {
		conn, err := listener.Accept()
		if err != nil {
			return err
		}
		go tunnel.forward(conn)
	}
}

func (tunnel *SSHtunnel) forward(localConn net.Conn) {
	serverConn, err := ssh.Dial("tcp", tunnel.Server.String(), tunnel.Config)
	if err != nil {
		fmt.Printf("Server dial error: %s\n", err)
		return
	}

	remoteConn, err := serverConn.Dial("tcp", tunnel.Remote.String())
	if err != nil {
		fmt.Printf("Remote dial error: %s\n", err)
		return
	}

	copyConn:=func(writer, reader net.Conn) {
		_, err:= io.Copy(writer, reader)
		if err != nil {
			fmt.Printf("io.Copy error: %s", err)
		}
	}

	go copyConn(localConn, remoteConn)
	go copyConn(remoteConn, localConn)
}

func SSHAgent() ssh.AuthMethod {
	if sshAgent, err := net.Dial("unix", os.Getenv("SSH_AUTH_SOCK")); err == nil {
		return ssh.PublicKeysCallback(agent.NewClient(sshAgent).Signers)
	}
	return nil
}

func StartTunnelIfNeeded(config RequesterConfig) {
	if len(config.SshBastion) > 0 {
		
		if !strings.HasPrefix(config.SshBastion, "ssh://") {
			fmt.Printf("Bastion host must start with ssh://. Exiting\n")
			os.Exit(1)
		}
		
		bastion_parsed, err := url.Parse(config.SshBastion)
		if err != nil {
			fmt.Printf("url.Parse error for SshBastion: %s", err)
		}
		
		// Check to see if it's a nonstardard port
		host_parts := strings.Split(bastion_parsed.Host, ":")
		var ssh_port int
		ssh_port = 22
		if len(host_parts) == 2 {
			var err error
			ssh_port, err = strconv.Atoi(host_parts[1])
			if err != nil {
				fmt.Printf("strconv.Atoi error: %s", err)
			}
		}
		
		// Get remote end information
		remote_parsed, err := url.Parse(config.SignerUrl)
		if err != nil {
			fmt.Printf("url.Parse error on SignerUrl: %s", err)
		}
		remote_parts := strings.Split(remote_parsed.Host, ":")
		if len(remote_parts) != 2 {
			fmt.Printf("Missing port for SignerUrl. Exiting")
			os.Exit(1)
		}
		remote_port, err := strconv.Atoi(remote_parts[1])
		if err != nil {
			fmt.Printf("strconv.Atoi error: %s", err)
		}
		
		fmt.Printf("config stuff: %s, %d\n", host_parts[0], ssh_port)
		fmt.Printf("starting tunnel config...\n")
		localEndpoint := &Endpoint{
			Host: "localhost",
			Port: 8080,
		}

		serverEndpoint := &Endpoint{
			Host: host_parts[0],
			Port: ssh_port,
		}

		remoteEndpoint := &Endpoint{
			Host: remote_parts[0],
			Port: remote_port,
		}

		sshConfig := &ssh.ClientConfig{
			User: bastion_parsed.User,
			Auth: []ssh.AuthMethod{
				SSHAgent(),
			},
			// TODO: fix this to actually check the trusted hosts
			// https://utcc.utoronto.ca/~cks/space/blog/programming/GoSSHHostKeyCheckingNotes
			HostKeyCallback: func(hostname string, remote net.Addr, key ssh.PublicKey) error {
				return nil
			},
		}

		tunnel := &SSHtunnel{
			Config: sshConfig,
			Local:  localEndpoint,
			Server: serverEndpoint,
			Remote: remoteEndpoint,
		}
		
		fmt.Printf("starting tunnel...\n")
		go tunnel.Start()
		
		fmt.Printf("doing normal stuff...\n")
		// end new stuff
	}
}

//func main() {
	//localEndpoint := &Endpoint{
		//Host: "localhost",
		//Port: 9000,
	//}

	//serverEndpoint := &Endpoint{
		//Host: "example.com",
		//Port: 22,
	//}

	//remoteEndpoint := &Endpoint{
		//Host: "localhost",
		//Port: 8080,
	//}

	//sshConfig := &ssh.ClientConfig{
		//User: "vcap",
		//Auth: []ssh.AuthMethod{
			//SSHAgent(),
		//},
	//}

	//tunnel := &SSHtunnel{
		//Config: sshConfig,
		//Local:  localEndpoint,
		//Server: serverEndpoint,
		//Remote: remoteEndpoint,
	//}

	//tunnel.Start()
//}	
