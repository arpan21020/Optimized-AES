<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>AES Implementation in Python</title>
    <style>
        body {
            font-family: Arial, sans-serif;
            line-height: 1.6;
            max-width: 800px;
            margin: 0 auto;
            padding: 20px;
        }
        h1, h2, h3 {
            color: #03396b;
        }
        code {
            background-color: #698695;
            padding: 2px 4px;
            border-radius: 4px;
            font-family: 'Courier New', Courier, monospace;
            color:#ffffff;
        }   
        pre {
            background-color: #698695;
            padding: 15px;
            border-radius: 4px;
            overflow-x: auto;
        }
        .highlight {
            background-color: #fff3cd;
            padding: 15px;
            border-radius: 4px;
            margin: 10px 0;
        }
        .optimization-section {
            padding: 15px;
            border-radius: 4px;
            margin: 10px 0;
        }
        .warning {
            background-color: #ffe7e7;
            padding: 15px;
            border-radius: 4px;
            margin: 10px 0;
        }
    </style>
</head>
<body>
    <h1>AES (Advanced Encryption Standard) Implementation</h1>
    <h2>Overview</h2>
    <p>This is a Python implementation of the AES encryption algorithm using NumPy. The implementation supports AES-128 encryption and decryption with the following features:</p>
    <ul>
        <li>Key expansion</li>
        <li>Block encryption</li>
        <li>Block decryption</li>
        <li>Support for string and byte array inputs</li>
        <li>Parallel processing capabilities</li>
    </ul>
    <h2>Current Optimizations</h2>
    <div class="optimization-section">
        <h3>1. NumPy Optimizations</h3>
        <ul>
            <li>Efficient matrix operations using NumPy arrays</li>
            <li>Vectorized operations in mixColumns and invMixColumns</li>
            <li>Optimized array manipulations using np.roll for ShiftRows</li>
        </ul>
        <h3>2. Lookup Table Optimizations</h3>
        <ul>
            <li>Pre-computed S-box and inverse S-box tables</li>
            <li>Pre-computed Galois Field multiplication tables (GF_MUL_2, GF_MUL_3, etc.)</li>
            <li>Avoids expensive runtime calculations</li>
        </ul>
        <h3>3. Parallel Processing</h3>
        <ul>
            <li>ThreadPoolExecutor implementation for multiple block processing</li>
            <li>Concurrent execution of encryption operations</li>
        </ul>
    </div>
    <h2>Usage</h2>
    <p>Basic usage example:</p>
    <pre><code>
# Initialize AES
aes = AES()
# Prepare key and input
key = np.array([
    0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
    0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c
], dtype=np.uint8)
input_block = np.array([
    0x32, 0x43, 0xf6, 0xa8, 0x88, 0x5a, 0x30, 0x8d,
    0x31, 0x31, 0x98, 0xa2, 0xe0, 0x37, 0x07, 0x34
], dtype=np.uint8)

#Key expansion
expanded_key = aes.keyExpansion(key, Nk=4, Nr=10)

#Encryption
encrypted_block = aes.cipher(input_block, Nr=10, w=expanded_key)

#Decryption
decrypted_block = aes.invCipher(encrypted_block, Nr=10, w=expanded_key)</code></pre>
    <h2>Dependencies</h2>
    <ul>
        <li>NumPy: For efficient array operations</li>
        <li>concurrent.futures (standard library): For parallel processing</li>
    </ul>
</body>
</html>