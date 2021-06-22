package annotationpublisher

import (
	"context"
	"fmt"
	"os"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/util/retry"
)

type AnnotationPublisher struct {
	clientset *kubernetes.Clientset

	selfNodeName     string
	selfPodName      string
	selfPodNamespace string
}

func NewAnnotationPublisher() (*AnnotationPublisher, error) {
	// creates the in-cluster config
	config, err := rest.InClusterConfig()
	if err != nil {
		return nil, err
	}
	// creates the clientset
	clientset, err := kubernetes.NewForConfig(config)
	if err != nil {
		return nil, err
	}

	a := &AnnotationPublisher{
		clientset:        clientset,
		selfNodeName:     os.Getenv("TRACELOOP_NODE_NAME"),
		selfPodName:      os.Getenv("TRACELOOP_POD_NAME"),
		selfPodNamespace: os.Getenv("TRACELOOP_POD_NAMESPACE"),
	}

	if a.selfNodeName == "" {
		return nil, fmt.Errorf("Environment variable TRACELOOP_NODE_NAME not set")
	}
	if a.selfPodName == "" {
		return nil, fmt.Errorf("Environment variable TRACELOOP_POD_NAME not set")
	}
	if a.selfPodNamespace == "" {
		return nil, fmt.Errorf("Environment variable TRACELOOP_POD_NAMESPACE not set")
	}

	return a, nil
}

func (a *AnnotationPublisher) Publish(data string) error {
	retryErr := retry.RetryOnConflict(retry.DefaultRetry, func() error {
		pod, err := a.clientset.CoreV1().Pods(a.selfPodNamespace).Get(context.TODO(), a.selfPodName, metav1.GetOptions{})
		if err != nil {
			return err
		}

		if pod.ObjectMeta.Annotations == nil {
			pod.ObjectMeta.Annotations = map[string]string{}
		}
		pod.ObjectMeta.Annotations["traceloop.kinvolk.io/state"] = data

		_, updateErr := a.clientset.CoreV1().Pods(a.selfPodNamespace).Update(context.TODO(), pod, metav1.UpdateOptions{})
		return updateErr
	})
	if retryErr != nil {
		return retryErr
	}

	return nil
}
