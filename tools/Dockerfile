FROM python:2.7.17

COPY requirements.txt /tmp/

RUN pip install --requirement /tmp/requirements.txt


RUN pip install \
        boto3 \
        dataclasses \
        nsenter \
        psutil \
        pycodestyle \
        pydocstyle \
        pylint \
        pytest \
        pytest-timeout \
        pyyaml \
        requests \
        requests-unixsocket \
        retry \
        typing-extensions


# WORKDIR /home/ubuntu/firecracker/firecracker/tools

RUN python -m pip freeze > /tmp/requirements-freeze.txt


#COPY /requirements-freeze.txt /tmp/


