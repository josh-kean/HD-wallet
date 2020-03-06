def addition(p, q):
    if p == q:
        s = (s*p[0]**2)/(2*p[1])
    else:
        s = (q[1]-p[1])/(q[0]-p[0])

    x3 = s**2-p[0]-q[0]%n #n is order of secp256k1
    y3 = s*(p[0]-x3)-p[1]%n #n is order of secp256k1
    return [x3, y3]

#cycles through the addition loop 'n' times
def multiplication(p, n):
    multiple = p
    while n > 0:
        multiple = addition(p, multiple)
        n -=1
    return multiple
