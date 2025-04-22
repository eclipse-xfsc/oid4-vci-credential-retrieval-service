include $(PWD)/.env

docker-compose-run:
	docker compose -f deployment/docker/docker-compose.yml -p $(PROJECT_NAME) --env-file=.env rm --force --stop
	docker-compose -f deployment/docker/docker-compose.yml -p $(PROJECT_NAME) --env-file=.env build --no-cache
	docker compose -f deployment/docker/docker-compose.yml -p $(PROJECT_NAME) --env-file=.env up --detach

build:
	docker compose -f deployment/docker/docker-compose.yml -p $(PROJECT_NAME) --env-file=.env rm --force --stop server
	docker-compose -f deployment/docker/docker-compose.yml -p $(PROJECT_NAME) --env-file=.env build server

restart: build
	docker compose -f deployment/docker/docker-compose.yml -p $(PROJECT_NAME) --env-file=.env up --detach server

update: build
	docker push $(IMAGE_REPO):$(IMAGE_TAG)

deploy:
	helm uninstall credential-verification-service  -n default --kubeconfig $(KUBECONFIG)
	helm install credential-verification-service  -n default deployment/helm --kubeconfig $(KUBECONFIG)

deploy-update: update deploy

swagger:
	swag init --parseDependency