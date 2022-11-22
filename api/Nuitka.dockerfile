FROM alpine:3.17 AS builder
RUN mkdir /app
WORKDIR /app
# Install dependencies:
RUN apk update && apk add --update musl-dev gcc patchelf python3-dev py3-pip chrpath wget make ccache
RUN pip install nuitka zstandard wheel
COPY requirements.txt /app/requirements.txt
RUN pip install -r /app/requirements.txt

# Build
COPY ./ /app
RUN python3 -m nuitka --onefile app.py

# Clean layer
FROM alpine:3.17
COPY --from=builder /app/app.bin /app/anchor
CMD ["./app/anchor"]