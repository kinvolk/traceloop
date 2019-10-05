/*
Copyright 2017 The Kubernetes Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

/* Code initially taken from the official client-go example:
 * https://github.com/kubernetes/client-go/blob/master/examples/workqueue/main.go
 * and adapted for traceloop.
 */

/* Package podinformer keeps track of pods with the containerIDs.
 *
 * Equivalent information can be retrieved with:
 * kubectl get pods -o=jsonpath='{.items[*].status.containerStatuses[*].containerID}'
 */
package podinformer

import (
	"fmt"
	"time"

	"k8s.io/klog"

	v1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/apimachinery/pkg/util/runtime"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/util/workqueue"

	_ "k8s.io/client-go/plugin/pkg/client/auth"
)

type PodInformer struct {
	indexer  cache.Indexer
	queue    workqueue.RateLimitingInterface
	informer cache.Controller

	stop chan struct{}

	slotByContainerID map[string]int
	containerIDsByKey map[string][]string
}

func NewPodInformer() (*PodInformer, error) {
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

	// create the pod watcher
	podListWatcher := cache.NewListWatchFromClient(clientset.CoreV1().RESTClient(), "pods", v1.NamespaceDefault, fields.Everything())

	// creates the queue
	queue := workqueue.NewRateLimitingQueue(workqueue.DefaultControllerRateLimiter())

	indexer, informer := cache.NewIndexerInformer(podListWatcher, &v1.Pod{}, 0, cache.ResourceEventHandlerFuncs{
		AddFunc: func(obj interface{}) {
			key, err := cache.MetaNamespaceKeyFunc(obj)
			if err == nil {
				queue.Add(key)
			}
		},
		UpdateFunc: func(old interface{}, new interface{}) {
			key, err := cache.MetaNamespaceKeyFunc(new)
			if err == nil {
				queue.Add(key)
			}
		},
		DeleteFunc: func(obj interface{}) {
			// IndexerInformer uses a delta queue, therefore for deletes we have to use this
			// key function.
			key, err := cache.DeletionHandlingMetaNamespaceKeyFunc(obj)
			if err == nil {
				queue.Add(key)
			}
		},
	}, cache.Indexers{})

	p := &PodInformer{
		indexer:           indexer,
		queue:             queue,
		informer:          informer,
		stop:              make(chan struct{}),
		slotByContainerID: make(map[string]int),
		containerIDsByKey: make(map[string][]string),
	}

	// Now let's start the controller
	go p.Run(1, p.stop)

	return p, nil
}

func (p *PodInformer) OnSlotClaimed(slot int, containerID string) {
	fmt.Printf("OnSlotClaimed: %v %v\n", slot, containerID)
	p.slotByContainerID[containerID] = slot
}

func (p *PodInformer) OnSlotFinished(slot int) {
	fmt.Printf("OnSlotFinished: %v\n", slot)

	// TODO: add a timer

	//for key := range p.slotByContainerID {
	//	if p.slotByContainerID[key] == slot {
	//		delete(p.slotByContainerID, key)
	//	}
	//}
}

func (p *PodInformer) GetSlotfromPod(namespace, podname string, containerIndex int) (int, error) {
	// See cache.MetaNamespaceKeyFunc()
	key := namespace + "/" + podname
	arr, ok := p.containerIDsByKey[key]
	if !ok {
		return -1, fmt.Errorf("pod %s not found", key)
	}
	if len(arr) <= containerIndex {
		return -1, fmt.Errorf("container #%d not found in pod %s", containerIndex, key)
	}
	containerID := arr[containerIndex]
	slot, ok := p.slotByContainerID[containerID]
	if !ok {
		return -1, fmt.Errorf("no logs for container %s in pod %s", containerID, key)
	}
	return slot, nil
}

func (p *PodInformer) GetSlotDescription(slot int) (namespace, podname string, containerIndex int, err error) {
	var containerID string
	for cid, s := range p.slotByContainerID {
		if s == slot {
			containerID = cid
			break
		}
	}
	if containerID == "" {
		return "", "", -1, fmt.Errorf("no containerID for slot #%d", slot)
	}
	for k, cids := range p.containerIDsByKey {
		ns, n, err2 := cache.SplitMetaNamespaceKey(k)
		if err2 != nil {
			return "", "", -1, err2
		}
		for i, cid := range cids {
			if cid == containerID {
				return ns, n, i, nil
			}
		}
	}
	return "", "", -1, fmt.Errorf("slot #%d not found", slot)
}

func (p *PodInformer) Stop() {
	close(p.stop)
}

func (p *PodInformer) processNextItem() bool {
	// Wait until there is a new item in the working queue
	key, quit := p.queue.Get()
	if quit {
		return false
	}
	// Tell the queue that we are done with processing this key. This unblocks the key for other workers
	// This allows safe parallel processing because two pods with the same key are never processed in
	// parallel.
	defer p.queue.Done(key)

	// Invoke the method containing the business logic
	err := p.syncToStdout(key.(string))
	// Handle the error if something went wrong during the execution of the business logic
	p.handleErr(err, key)
	return true
}

// syncToStdout is the business logic of the controller. In this controller it simply prints
// information about the pod to stdout. In case an error happened, it has to simply return the error.
// The retry logic should not be part of the business logic.
func (p *PodInformer) syncToStdout(key string) error {
	obj, exists, err := p.indexer.GetByKey(key)
	if err != nil {
		klog.Errorf("Fetching object with key %s from store failed with %v", key, err)
		return err
	}

	if !exists {
		// Below we will warm up our cache with a Pod, so that we will see a delete for one pod
		fmt.Printf("Pod %s does not exist anymore\n", key)
		delete(p.containerIDsByKey, key)
	} else {
		// Note that you also have to check the uid if you have a local controlled resource, which
		// is dependent on the actual instance, to detect that a Pod was recreated with the same name
		fmt.Printf("Sync/Add/Update for Pod %s %s:\n",
			obj.(*v1.Pod).GetNamespace(), obj.(*v1.Pod).GetName())
		p.containerIDsByKey[key] = nil
		for _, s := range obj.(*v1.Pod).Status.ContainerStatuses {
			fmt.Printf("    %s\n", s.ContainerID)
			p.containerIDsByKey[key] = append(p.containerIDsByKey[key], s.ContainerID)
		}
	}
	return nil
}

// handleErr checks if an error happened and makes sure we will retry later.
func (p *PodInformer) handleErr(err error, key interface{}) {
	if err == nil {
		// Forget about the #AddRateLimited history of the key on every successful synchronization.
		// This ensures that future processing of updates for this key is not delayed because of
		// an outdated error history.
		p.queue.Forget(key)
		return
	}

	// This controller retries 5 times if something goes wrong. After that, it stops trying.
	if p.queue.NumRequeues(key) < 5 {
		klog.Infof("Error syncing pod %v: %v", key, err)

		// Re-enqueue the key rate limited. Based on the rate limiter on the
		// queue and the re-enqueue history, the key will be processed later again.
		p.queue.AddRateLimited(key)
		return
	}

	p.queue.Forget(key)
	// Report to an external entity that, even after several retries, we could not successfully process this key
	runtime.HandleError(err)
	klog.Infof("Dropping pod %q out of the queue: %v", key, err)
}

func (p *PodInformer) Run(threadiness int, stopCh chan struct{}) {
	defer runtime.HandleCrash()

	// Let the workers stop when we are done
	defer p.queue.ShutDown()
	klog.Info("Starting Pod controller")

	go p.informer.Run(stopCh)

	// Wait for all involved caches to be synced, before processing items from the queue is started
	if !cache.WaitForCacheSync(stopCh, p.informer.HasSynced) {
		runtime.HandleError(fmt.Errorf("Timed out waiting for caches to sync"))
		return
	}

	for i := 0; i < threadiness; i++ {
		go wait.Until(p.runWorker, time.Second, stopCh)
	}

	<-stopCh
	klog.Info("Stopping Pod controller")
}

func (p *PodInformer) runWorker() {
	for p.processNextItem() {
	}
}
