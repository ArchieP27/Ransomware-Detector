def drawingEdge():
    MOD = 10**9 + 7

    # User input for number of vertices
    n = int(input()))

    # Calculate the number of edges in a complete graph
    edges = (n * (n - 1)) // 2

    # Modular exponentiation
    def modular_exponentiation(base, exp, mod):
        result = 1
        while exp > 0:
            if exp % 2 == 1:  # If exponent is odd
                result = (result * base) % mod
            base = (base * base) % mod
            exp //= 2
        return result

    # Compute the result
    result = modular_exponentiation(2, edges, MOD)
    print(f"The number of distinct graphs that can be formed with {n} vertices is: {result}")

# Call the function
drawingEdge()