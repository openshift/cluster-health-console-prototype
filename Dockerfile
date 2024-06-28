FROM registry.access.redhat.com/ubi8/python-311

# Setup env
ENV LANG C.UTF-8
ENV LC_ALL C.UTF-8
ENV PYTHONDONTWRITEBYTECODE 1
ENV PYTHONFAULTHANDLER 1
ENV PIP_NO_CACHE_DIR=off
ENV PIP_DISABLE_PIP_VERSION_CHECK=on
ENV PIP_DEFAULT_TIMEOUT=100
ENV POETRY_VERSION=1.0.0

# Add application sources with correct permissions for OpenShift
USER root
# install certs and compilation deps
RUN pip install poetry

RUN mkdir -p /opt/app-root
RUN chown -R 1001:0 /opt/app-root

WORKDIR /opt/app-root
COPY assets ./assets
COPY app.py poetry.lock pyproject.toml .

USER default

# Install the dependencies
RUN poetry config virtualenvs.create true && \
  poetry config virtualenvs.in-project true && \
  poetry install --no-interaction --no-ansi

ENV PATH="/opt/app-root/.venv/bin:$PATH"

CMD [".venv/bin/python", "app.py"]
EXPOSE 8050
