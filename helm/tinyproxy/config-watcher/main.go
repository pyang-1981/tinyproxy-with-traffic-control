package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"os/exec"
	"os/signal"
	"syscall"
	"time"

	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/watch"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
)

func copyFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.Create(dst)
	if err != nil {
		return err
	}
	defer out.Close()
	if _, err := io.Copy(out, in); err != nil {
		return err
	}
	return out.Sync()
}

func writeConfigFromData(data, dst string) error {
	out, err := os.Create(dst)
	if err != nil {
		return err
	}
	defer out.Close()
	if _, err := out.WriteString(data); err != nil {
		return err
	}
	return out.Sync()
}

func signalTinyproxy() error {
	log.Printf("sending SIGUSR1 to tinyproxy")
	cmd := exec.Command("pkill", "-USR1", "tinyproxy")
	if err := cmd.Run(); err != nil {
		log.Printf("failed to send SIGUSR1: %v", err)
		return err
	}
	log.Printf("SIGUSR1 sent successfully to tinyproxy")
	return nil
}

type configUpdate struct {
	data string
}

func watchConfigMap(ctx context.Context, namespace, configMapName, configKey string, configChanges chan<- configUpdate) {
	// Create in-cluster config
	config, err := rest.InClusterConfig()
	if err != nil {
		log.Printf("failed to create in-cluster config: %v (falling back to polling)", err)
		return
	}

	clientset, err := kubernetes.NewForConfig(config)
	if err != nil {
		log.Printf("failed to create kubernetes client: %v (falling back to polling)", err)
		return
	}

	log.Printf("watching ConfigMap %s/%s for changes via Kubernetes API", namespace, configMapName)

	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		watcher, err := clientset.CoreV1().ConfigMaps(namespace).Watch(ctx, metav1.ListOptions{
			FieldSelector: fmt.Sprintf("metadata.name=%s", configMapName),
		})
		if err != nil {
			log.Printf("failed to watch ConfigMap: %v, retrying in 5s", err)
			time.Sleep(5 * time.Second)
			continue
		}

		for event := range watcher.ResultChan() {
			if event.Type == watch.Modified {
				cm, ok := event.Object.(*v1.ConfigMap)
				if !ok {
					log.Printf("unexpected object type in watch event")
					continue
				}

				configData, exists := cm.Data[configKey]
				if !exists {
					log.Printf("ConfigMap key %s not found", configKey)
					continue
				}

				log.Printf("ConfigMap change detected via Kubernetes API, reading new config")
				select {
				case configChanges <- configUpdate{data: configData}:
				default:
					// Channel full, skip this event
					log.Printf("config change channel full, skipping event")
				}
			}
		}

		log.Printf("watch connection closed, reconnecting in 1s")
		time.Sleep(1 * time.Second)
	}
}

func main() {
	src := flag.String("src", "/config/tinyproxy.conf", "source config path")
	dst := flag.String("dst", "/config-data/tinyproxy.conf", "destination config path")
	once := flag.Bool("once", false, "run one-time copy and exit (for initContainers)")
	configMapName := flag.String("configmap", "tinyproxy-tinyproxy-config", "ConfigMap name to watch")
	namespace := flag.String("namespace", "", "Kubernetes namespace (auto-detected if empty)")
	flag.Parse()

	log.Printf("config-watcher starting: src=%s dst=%s once=%v", *src, *dst, *once)

	// initial copy (best-effort)
	if err := copyFile(*src, *dst); err != nil {
		log.Printf("initial copy failed: %v", err)
	}

	if *once {
		log.Printf("one-shot mode enabled, exiting after initial copy")
		return
	}

	// Detect namespace if not provided
	if *namespace == "" {
		nsBytes, err := os.ReadFile("/var/run/secrets/kubernetes.io/serviceaccount/namespace")
		if err != nil {
			log.Printf("failed to read namespace from service account: %v, using 'default'", err)
			*namespace = "default"
		} else {
			*namespace = string(nsBytes)
		}
	}

	// handle termination gracefully
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigs
		log.Printf("shutting down")
		cancel()
	}()

	// Channel for ConfigMap change events from API watch
	configChanges := make(chan configUpdate, 10)

	// Start watching ConfigMap via Kubernetes API
	// Extract config key from source file (default: "tinyproxy.conf")
	configKey := "tinyproxy.conf"
	go watchConfigMap(ctx, *namespace, *configMapName, configKey, configChanges)

	for {
		select {
		case <-ctx.Done():
			return
		case update := <-configChanges:
			// ConfigMap changed via API watch, write new config immediately
			log.Printf("writing new config from Kubernetes API")
			if err := writeConfigFromData(update.data, *dst); err != nil {
				log.Printf("failed to write config from API: %v", err)
				continue
			}
			if err := signalTinyproxy(); err != nil {
				log.Printf("failed to signal tinyproxy: %v", err)
				continue
			}
			log.Printf("config reloaded from Kubernetes API")
		}
	}
}
