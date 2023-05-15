# Importing standard Qiskit libraries
import base64
import math

from qiskit import *
from bitstring import BitArray

def QRNG_GEN(who):
    # Create a Quantum Register with 6 qubits.
    qr = QuantumRegister(6)

    # Create a Classical Register with 6 bits.
    cr = ClassicalRegister(6)

    # Create a Quantum Circuit
    qc = QuantumCircuit(qr, cr)

    # Add a H gate on qubit 0 to 5, putting these qubits in superposition.
    qc.h(qr[0])
    qc.h(qr[1])
    qc.h(qr[2])
    qc.h(qr[3])
    qc.h(qr[4])
    qc.h(qr[5])

    # Add a CX (CNOT) gate on control qubit 0 and target qubit 1, putting
    # the qubits in a Bell state.
    qc.cx(qr[0], qr[1])

    # Add a CX (CNOT) gate on control qubit 0 and target qubit 2.
    qc.cx(qr[0], qr[2])

    # Add a CX (CNOT) gate on control qubit 0 and target qubit 3.
    qc.cx(qr[0], qr[3])

    # Add a CX (CNOT) gate on control qubit 0 and target qubit 4.
    qc.cx(qr[0], qr[4])

    # Add a CX (CNOT) gate on control qubit 0 and target qubit 5.
    qc.cx(qr[0], qr[5])

    # Add a CCX (Toffoli) gate on control qubits 1 and 2 and target qubit 3.
    qc.ccx(qr[1], qr[2], qr[3])

    # Add a CCX (Toffoli) gate on control qubits 1 and 2 and target qubit 4.
    qc.ccx(qr[1], qr[2], qr[4])

    # Add a CCX (Toffoli) gate on control qubits 1 and 2 and target qubit 5.
    qc.ccx(qr[1], qr[2], qr[5])

    # Add a CCX (Toffoli) gate on control qubits 3 and 4 and target qubit 5.
    qc.ccx(qr[3], qr[4], qr[5])

    # Add a Measure gate to see the state.
    qc.measure(qr, cr)

    # See a list of available local simulators
    print("Aer backends: ", Aer.backends())

    # Choose an accuracy level and a confidence level
    epsilon = 0.01  # You can change this according to your preference
    delta = 0.001  # You can change this according to your preference

    # Use Hoeffding's inequality to estimate the number of shots
    n = math.ceil((1 / 2) ** 2 / (2 * epsilon ** 2) * math.log(
        2 / delta))  # You can comment this out if you want to use Chebyshev's inequality

    # Use Chebyshev's inequality to estimate the number of shots
    # n = math.ceil(0.25/(epsilon**2*delta)) # You can uncomment this if you want to use Chebyshev's inequality

    # Print the number of shots
    print('Number of shots:', n)

    # Choose a backend to run the circuit
    backend = Aer.get_backend('qasm_simulator')

    # Execute the circuit on the backend using the execute function
    job = execute(qc, backend=backend, shots=n)

    # Get the result object from the job
    result = job.result()

    # Show the results as counts of measurement outcomes
    counts = result.get_counts()
    print(counts)

    # Convert the counts to a binary string
    bitstring = ''
    for outcome in counts:
        bitstring += outcome * counts[outcome]

    # Truncate the bitstring to get a nonce of 192 bits
    nonce = bitstring[:96]
    print(len(nonce))
    he = hex(int(nonce, 2))
    nonce = BitArray(hex=he)
    # nonce = _bitstring_to_bytes(nonce)
    # Print the nonce
    print(who,"'s s Nonce:", nonce.tobytes())

    return (nonce.tobytes())


def _bitstring_to_bytes(s):
    res = int(s, 2).to_bytes((len(s) + 7) // 8, 'big')

    return res

print(b"ff, ",QRNG_GEN("MEAW"))