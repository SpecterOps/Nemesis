# Creating a New Service

1. Create a new folder in `/cmd/` with `poetry new NAME`
    - Add dependencies as needed with `poetry add LIBRARY`, and then `poetry lock` to lock the dependencies in
    - Follow an existing module like `dotnet` to see how the Dockerfile should be structured for Poetry.
2. Create/test a <SERVICE>.Dockerfile and place it in in ./dockerfiles/
    - You can build the dockerfile independently with `~/ods$ docker build -f ./dockerfiles/<SERVICE>.Dockerfile .`
3. In **./helm/nemesis/templates/** create (based on existing examples):
    - `./<SERVICE>.deployment.yaml`
    - `./<SERVICE>.service.yaml`
4. In skaffold.yaml:
    - Add the service under the build, profile/artifacts, and kubectl/manifests sections
    - (Optionally) Expose the port in the portForward section
