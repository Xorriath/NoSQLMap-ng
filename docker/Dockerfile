# The codebase is Python 3.  Build the LOCAL package (not the old upstream repo)
# on a Python 3 base.  docker-compose sets the build context to the repo root.
FROM python:3.12-slim

WORKDIR /app
COPY . /app

RUN pip install --no-cache-dir .

ENTRYPOINT ["nosqlmap-ng"]
