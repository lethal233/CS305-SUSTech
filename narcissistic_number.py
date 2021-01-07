def find_narcissistic_number(start: int, end: int) -> list:
    list = []
    for i in range(start, end):
        temp = 0
        string = str(i)
        length = len(string)
        temp = 0
        for j in range(length):
            temp = temp + int(string[j])**length
        if temp == i:
            list.append(i)
    return list
