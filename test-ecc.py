from ecc import FieldElement, Point

a = FieldElement(3, 31)
b = FieldElement(24, 31)

print(a / b == FieldElement(4, 31))

p1 = Point(-1, -1, 5, 7)
# points not on the curve
#p2 = Point(-1, -2, 5, 7)
#p3 = Point(2, 4, 5, 7)
#p4 = Point(5, 7, 5, 7)
p5 = Point(18, 77, 5, 7)

point_a = Point(3, -7, 5, 7)
point_b = Point(18, 77, 5, 7)
print(point_a != point_b)
print(point_a != point_a)

# Exercise 2
p_1 = Point(-1, -1, 5, 7)
p_2 = Point(-1, 1, 5, 7)
inf = Point(None, None, 5, 7)
print(p_1 + inf)
print(inf + p_2)
print(p_1 + p_2)


# Exercise 4
a = 5
b = 7
x1, y1 = 2, 5
x2, y2 = -1, -1

point_a = Point(x1, y1, a, b)
point_b = Point(x2, y2, a, b)
print(point_a + point_b)

# Exercise 6
a = 5
b = 7
x1, y1 = -1, 1
point_a = Point(x1, y1, a, b)
point_b = Point(x1, y1, a, b)
print(point_a + point_b)
# (-1,1) + (-1,1)