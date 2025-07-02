package upgrade

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"math/rand"
	"net/http"
	"os"
	"os/exec"
	"strconv"
	"testing"
	"time"

	"github.com/cenkalti/backoff"
	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/api/types/filters"
	"github.com/docker/docker/client"
	"github.com/notawar/mobius/pkg/mobiushttp"
	"github.com/notawar/mobius/server/service"
	_ "github.com/go-sql-driver/mysql"
	"github.com/jmoiron/sqlx"
)

func init() {
	rand.Seed(time.Now().Unix())
}

// Mobius represents the mobius server and its dependencies used for testing.
type Mobius struct {
	// ProjectName is the docker compose project name
	ProjectName string
	// FilePath is the path to the docker-compose.yml
	FilePath string
	// Version is the active mobius version.
	Version string
	// Token is the mobius token used for authentication
	Token string

	dockerClient client.ContainerAPIClient
	t            *testing.T
}

// NewMobius starts mobius and it's dependencies with the specified version.
func NewMobius(t *testing.T, version string) *Mobius {
	// don't use test name because it will be normalized
	//nolint:gosec // does not need to be secure for tests
	projectName := "mobius-test-" + strconv.FormatUint(rand.Uint64(), 16)

	dockerClient, err := client.NewClientWithOpts(client.FromEnv, client.WithAPIVersionNegotiation())
	if err != nil {
		t.Fatalf("create docker client: %v", err)
	}

	f := &Mobius{
		ProjectName:  projectName,
		FilePath:     "docker-compose.yml",
		Version:      version,
		dockerClient: dockerClient,
		t:            t,
	}

	t.Cleanup(f.cleanup)

	if err := f.Start(); err != nil {
		t.Fatalf("start mobius version A: %v", err)
	}

	return f
}

func (f *Mobius) Start() error {
	env := map[string]string{
		"MOBIUS_VERSION": f.Version,
	}
	_, err := f.execCompose(env, "pull")
	if err != nil {
		return err
	}

	// start mysql and wait until ready
	_, err = f.execCompose(env, "up", "--remove-orphans", "-d", "mysql")
	if err != nil {
		return err
	}
	if err := f.waitMYSQL(); err != nil {
		return err
	}

	// run the migrations using the mobius starting version
	_, err = f.execCompose(env, "run", "-T", "mobius", "mobius", "prepare", "db", "--no-prompt")
	if err != nil {
		return err
	}

	// start mobius
	_, err = f.execCompose(env, "up", "--remove-orphans", "-d", "mobius", "mobius")
	if err != nil {
		return err
	}

	if err := f.waitMobius(); err != nil {
		return err
	}

	if err := f.setupMobius(); err != nil {
		return err
	}

	return nil
}

// Client returns a mobius client that uses the mobius API.
func (f *Mobius) Client() (*service.Client, error) {
	port, err := f.getPublicPort("mobius", 8080)
	if err != nil {
		return nil, fmt.Errorf("get mobius port: %v", err)
	}

	address := fmt.Sprintf("https://localhost:%d", port)
	client, err := service.NewClient(address, true, "", "")
	if err != nil {
		return nil, err
	}

	client.SetToken(f.Token)

	return client, nil
}

func (f *Mobius) setupMobius() error {
	client, err := f.Client()
	if err != nil {
		return err
	}

	token, err := client.Setup("admin@example.com", "Admin", "password123#", "Mobius Test")
	if err != nil {
		return err
	}
	f.Token = token

	return nil
}

func (f *Mobius) waitMYSQL() error {
	f.t.Log("waiting for MySQL container to respond...")

	// get the random mysql host port assigned by docker
	port, err := f.getPublicPort("mysql", 3306)
	if err != nil {
		return err
	}

	dsn := fmt.Sprintf("mobius:mobius@tcp(localhost:%d)/mobius", port)
	f.t.Logf("dsn: %s", dsn)

	retryInterval := 5 * time.Second
	timeout := 5 * time.Minute

	ticker := time.NewTicker(retryInterval)
	defer ticker.Stop()

	timeoutChan := time.After(timeout)
	for {
		select {
		case <-timeoutChan:
			return fmt.Errorf("db connection failed after %s", timeout)
		case <-ticker.C:
			db, err := sqlx.Connect("mysql", dsn)
			if err != nil {
				fmt.Fprintf(os.Stderr, "failed to connect to db: %v\n", err)
			} else {
				db.Close()
				return nil
			}
		}
	}
}

func (f *Mobius) getPublicPort(serviceName string, privatePort uint16) (uint16, error) {
	containerName := fmt.Sprintf("%s-%s-1", f.ProjectName, serviceName)

	// get the random mobius host port assigned by docker
	argsName := filters.Arg("name", containerName)
	containers, err := f.dockerClient.ContainerList(context.TODO(), container.ListOptions{Filters: filters.NewArgs(argsName)})
	if err != nil {
		return 0, err
	}
	if len(containers) == 0 {
		return 0, errors.New("no containers found")
	}
	for _, port := range containers[0].Ports {
		if port.PrivatePort == privatePort {
			return port.PublicPort, nil
		}
	}
	return 0, errors.New("private port not found")
}

func (f *Mobius) waitMobius() error {
	f.t.Logf("waiting for mobius %s to be healthy...", f.Version)

	containerName := fmt.Sprintf("%s-mobius-1", f.ProjectName)

	// get the random mobius host port assigned by docker
	argsName := filters.Arg("name", containerName)
	containers, err := f.dockerClient.ContainerList(context.TODO(), container.ListOptions{Filters: filters.NewArgs(argsName), All: true})
	if err != nil {
		return err
	}
	if len(containers) == 0 {
		return errors.New("no mobius container found")
	}
	port := containers[0].Ports[0].PublicPort
	healthURL := fmt.Sprintf("https://localhost:%d/healthz", port)
	f.t.Logf("mobius URL: %s", healthURL)

	retryStrategy := backoff.NewExponentialBackOff()
	retryStrategy.MaxInterval = 1 * time.Second

	//nolint:gosec // G107: Ok to trust docker here
	client := mobiushttp.NewClient(mobiushttp.WithTLSClientConfig(&tls.Config{InsecureSkipVerify: true}))

	if err := backoff.Retry(
		func() error {
			resp, err := client.Get(healthURL)
			if err != nil {
				return err
			}
			if resp.StatusCode != http.StatusOK {
				return fmt.Errorf("non-200 status code: %d", resp.StatusCode)
			}
			return nil
		},
		retryStrategy,
	); err != nil {
		return fmt.Errorf("check health: %v", err)
	}
	f.t.Log("mobius is healthy")

	return nil
}

func (f *Mobius) cleanup() {
	output, err := f.execCompose(nil, "down", "-v", "--remove-orphans")
	if err != nil {
		fmt.Fprintf(os.Stderr, "stop mobius: %v %s", err, output)
	}
}

func (f *Mobius) execCompose(env map[string]string, args ...string) (string, error) {
	// docker compose variables via environment eg MOBIUS_VERSION_A
	e := os.Environ()
	for k, v := range env {
		e = append(e, fmt.Sprintf("%s=%s", k, v))
	}

	// prepend default args
	args = append([]string{
		"compose",
		"--project-name", f.ProjectName,
		"--file", f.FilePath,
	}, args...)

	var stdout, stderr bytes.Buffer

	cmd := exec.Command("docker", args...)
	f.t.Log(cmd.String())
	cmd.Env = e
	wout := io.MultiWriter(&stdout, os.Stdout)
	werr := io.MultiWriter(&stderr, os.Stderr)
	cmd.Stdout = wout
	cmd.Stderr = werr
	err := cmd.Run()
	if err != nil {
		return "", fmt.Errorf("docker: %v %s", err, stderr.String())
	}

	return stdout.String(), nil
}

// StartHost starts an osquery host using docker-compose and enrolls it with mobius.
// Returns the container ID which is also the hostname and osquery host ID.
func (f *Mobius) StartHost() (string, error) {
	// get the enroll secret
	client, err := f.Client()
	if err != nil {
		return "", err
	}

	enrollSecretSpec, err := client.GetEnrollSecretSpec()
	if err != nil {
		return "", err
	}
	if len(enrollSecretSpec.Secrets) == 0 {
		return "", errors.New("no enroll secret found")
	}

	enrollSecret := enrollSecretSpec.Secrets[0].Secret

	env := map[string]string{
		"ENROLL_SECRET": enrollSecret,
	}
	output, err := f.execCompose(env, "run", "--remove-orphans", "-d", "-T", "osquery")
	if err != nil {
		return "", err
	}

	// get the container id
	containerID := output[:len(output)-1] // strip the newline from output

	// inspect the container to get the hostname
	containerJSON, err := f.dockerClient.ContainerInspect(context.Background(), containerID)
	if err != nil {
		return "", fmt.Errorf("inspect container: %v", err)
	}
	hostname := containerJSON.Config.Hostname

	return hostname, nil
}

// Upgrade upgrades mobius to a specified version.
func (f *Mobius) Upgrade(from, to string) error {
	// stop mobius
	env := map[string]string{
		"MOBIUS_VERSION": from,
	}

	if _, err := f.execCompose(env, "rm", "-s", "-v", "mobius"); err != nil {
		return fmt.Errorf("bring mobius down: %v", err)
	}

	// run migrations
	env = map[string]string{
		"MOBIUS_VERSION": to,
	}
	// we need to pull the new version
	if _, err := f.execCompose(env, "pull"); err != nil {
		return err
	}
	if _, err := f.execCompose(env, "run", "--remove-orphans", "-T", "mobius", "mobius", "prepare", "db", "--no-prompt"); err != nil {
		return fmt.Errorf("run migrations: %v", err)
	}

	// start the new version
	if _, err := f.execCompose(env, "up", "--remove-orphans", "-d", "mobius", "mobius"); err != nil {
		return fmt.Errorf("start mobius version B: %v", err)
	}

	f.Version = to

	// wait until healthy
	if err := f.waitMobius(); err != nil {
		return fmt.Errorf("wait for mobius to be healthy: %v", err)
	}

	f.t.Log("upgraded successfully")

	return nil
}

func enrollHost(t *testing.T, f *Mobius) (string, error) {
	client, err := f.Client()
	if err != nil {
		return "", fmt.Errorf("creating mobius client: %w", err)
	}

	// enroll a host
	hostname, err := f.StartHost()
	if err != nil {
		return "", fmt.Errorf("creating mobius client: %w", err)
	}

	// wait until host is enrolled and software is listed
	retryStrategy := backoff.NewExponentialBackOff()
	retryStrategy.InitialInterval = 5 * time.Second
	retryStrategy.MaxInterval = 5 * time.Minute

	if err := backoff.Retry(func() error {
		host, err := client.HostByIdentifier(hostname)
		if err != nil {
			t.Logf("get host by identifier %s: %s", hostname, err)
			return err
		}

		if len(host.Software) == 0 {
			t.Logf("software for %s not reported yet", hostname)
			return errors.New("no software reported yet")
		}

		return nil
	}, retryStrategy); err != nil {
		return "", fmt.Errorf("host enroll retry: %w", err)
	}

	return hostname, nil
}
