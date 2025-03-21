#!/bin/bash

echo "Setting up RBAC..."
kubectl apply -f test-rbac.yaml

echo "Creating test pod..."
kubectl run nginx --image=nginx

echo "Testing as regular user alice..."
kubectl --as=alice get pods
kubectl --as=alice delete pod nginx

echo "Testing as privileged support user..."
kubectl --as=support get pods
kubectl --as=support delete pod nginx

echo "Testing protected resource deletion..."
kubectl run aks-automatic-test --image=nginx
echo "Trying to delete as regular user alice..."
kubectl --as=alice delete pod aks-automatic-test
echo "Trying to delete as support user..."
kubectl --as=support delete pod aks-automatic-test
