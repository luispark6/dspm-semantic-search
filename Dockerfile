FROM python:3.10

WORKDIR /code

COPY . /code

RUN pip3 install gradio==5.23.0

EXPOSE 7860

CMD [ "gradio", "frontend.py" ]

