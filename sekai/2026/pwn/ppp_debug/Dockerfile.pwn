FROM sekai-base 

ENV DEBIAN_FRONTEND=noninteractive

RUN apt update --fix-missing
RUN apt install -y git gdb wget patchelf file strace tmux python3 \ 
        netcat python3-pip ruby-full valgrind vim xclip elfutils \
        checksec socat procps

WORKDIR /opt
RUN git clone https://github.com/pwndbg/pwndbg
WORKDIR /opt/pwndbg
RUN git checkout 2024.08.29

RUN apt-get install -y curl
ENV PATH="/root/.local/bin:$PATH"
RUN curl -sSL https://install.python-poetry.org | POETRY_VERSION=1.8.4 python3 -

ENV LC_ALL=C.UTF-8
RUN ./setup.sh

WORKDIR /opt
RUN wget https://github.com/io12/pwninit/releases/download/3.3.3/pwninit
RUN chmod +x pwninit

RUN gem install elftools -v 1.2.0 && gem install one_gadget -v 1.9.0
RUN pip3 install pwntools IPython angr

WORKDIR /chall
CMD bash
