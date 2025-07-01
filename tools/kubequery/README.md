# Kubequery and Mobius

Use the provided configuration file ([kubequery-mobius.yml](kubequery-mobius.yml)) to get a [kubequery](../../infrastructure/kubequery) instance connected to Mobius.

Before deploying, first retrieve the enroll secret from Mobius by opening a web browser to the Mobius URL, going to the Hosts page, and clicking on the "Manage enroll secret" button.
Alternatively, you can get the enroll secret using `mobiuscli` using `mobiuscli get enroll-secret`.
Update the `enroll.secret` in the `ConfigMap`. In production, you will also need to update the `tls_hostname` and `mobius.pem` to the appropriate values. In order to download the `mobius.pem` certificate chain, navigate to the "Hosts> Add hosts> Advanced" tab and select "Download". Finally, deploy kubequery using `kubectl`

```sh
kubectl apply -f kubequery-mobius.yml
```

Kubernetes clusters will show up in Mobius with hostnames like `kubequery <CLUSTER NAME>`.

Sample queries are included in the configuration file ([queries-kubequery-mobius.yml](queries-kubequery-mobius.yml)). Modify the `team` value in this file to reflect the appropriate team name for your environment and apply with `mobiuscli`.

```
mobiuscli apply -f queries-kubequery-mobius.yml
```
