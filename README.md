# Harbor Snyk Scanner

Harbor Snyk Scanner is a scanner adaptor for [Harbor](https://goharbor.io) to integrate scan results from [Snyk](https://snyk.io).

> The project is currently work in progress and not ready to be used within production.

## Installation

The Harbor Snyk Scanner can be installed via [Helm](https://helm.sh/) or [Kustomize](https://kustomize.io).

To install the scanner via Helm you can use the following commands:

```sh
helm repo add ricoberger https://ricoberger.github.io/helm-charts
helm repo update

helm install harbor-snyk-scanner ricoberger/harbor-snyk-scanner
```

To install the scanner via Kustomize you can use the following commands:

```sh
kubectl create namespace harbor
kustomize build github.com/ricoberger/harbor-snyk-scanner/deploy/kustomize | kubectl apply -n harbor -f -
```
