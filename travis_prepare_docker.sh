export HOST_WORKDIR=`pwd`
export GITHUB_REPO=${GITHUB_REPO:-pmem/syscall_intercept}
export DOCKERHUB_REPO=${DOCKERHUB_REPO:-pmem/syscall_intercept}
export PROJECT=syscall_intercept
export EXTRA_DOCKER_ARGS=-t
cd utils/docker && \
./pull-or-rebuild-image.sh && \
if [[ -f push_image_to_repo_flag ]]; then PUSH_THE_IMAGE=1; fi && \
rm -f push_image_to_repo_flag
