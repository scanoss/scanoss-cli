import acme


def unsafe(path):
    return acme.load(path)


def safe(path):
    return acme.load(path, safe=True)
