
import typer

import os

app = typer.Typer()


@app.command()
def pk_create(byte_size: int = 8):
    k = os.urandom(byte_size)
    print(k.hex())
    print(k.hex(sep=' '))


def main():
    app()


if __name__ == "__main__":
    main()
