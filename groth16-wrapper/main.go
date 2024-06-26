package main

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"flag"
	"fmt"
	"math/big"
	"os"
	"strings"
	"time"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/consensys/gnark/backend"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/backend/witness"
	"github.com/consensys/gnark/constraint"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/succinctlabs/gnark-plonky2-verifier/goldilocks"
	"github.com/succinctlabs/gnark-plonky2-verifier/types"
	"github.com/succinctlabs/gnark-plonky2-verifier/variables"
	"github.com/succinctlabs/gnark-plonky2-verifier/verifier"
)

const plonky2VerifierFile = "verifier_only_circuit_data.json"
const plonky2CommonFile = "common_circuit_data.json"
const plonky2ProofFile = "proof_with_public_inputs.json"

const groth16CircuitFile = "circuit.bin"
const groth16ProvingKeyFile = "proving.key"
const groth16VerifyingKeyFile = "verifying.key"
const groth16SolidityVerifierFile = "Verifier.sol"
const groth16ProofFile = "proof.json"

const fileReaderBuffSize = 134217728

type VerifierCircuit struct {
	PublicInputs            []goldilocks.Variable             `gnark:",public"`
	Proof                   variables.Proof                   `gnark:",secret"`
	VerifierOnlyCircuitData variables.VerifierOnlyCircuitData `gnark:",constant"`

	// This is configuration for the circuit, it is a constant not a variable
	CommonCircuitData types.CommonCircuitData `gnark:",ignore"`
}

func (c *VerifierCircuit) Define(api frontend.API) error {
	verifierChip := verifier.NewVerifierChip(api, c.CommonCircuitData)
	verifierChip.Verify(c.Proof, c.PublicInputs, c.VerifierOnlyCircuitData)

	return nil
}

type SolidityProof struct {
    Proof         [8]string `json:"proof"`
    Commitments   []string  `json:"commitments"`
    CommitmentPok [2]string `json:"commitmentPok"`
    Input         []uint64  `json:"input"`
}

func groth16Proof(in string, out string, compressedKeys bool) {
	var err error
	ensureDir(out)

	// Get the compiled r1cs
	var r1csCompiled constraint.ConstraintSystem
	var r1csFile = out + groth16CircuitFile
	if fileExists(r1csFile) {
		fmt.Println("Loading r1cs", time.Now())

		fR1CS, _ := os.Open(r1csFile)
		reader := bufio.NewReaderSize(fR1CS, fileReaderBuffSize)
		r1csCompiled = groth16.NewCS(ecc.BN254)
		r1csCompiled.ReadFrom(reader)
		fR1CS.Close()

	} else {
		fmt.Println("Building r1cs", time.Now())

		verifierOnlyCircuitData := variables.DeserializeVerifierOnlyCircuitData(types.ReadVerifierOnlyCircuitData(in + plonky2VerifierFile))
		proofWithPis := variables.DeserializeProofWithPublicInputs(types.ReadProofWithPublicInputs(in + plonky2ProofFile))
		commonCircuitData := types.ReadCommonCircuitData(in + plonky2CommonFile)
		circuit := VerifierCircuit{
			Proof:                   proofWithPis.Proof,
			PublicInputs:            proofWithPis.PublicInputs,
			VerifierOnlyCircuitData: verifierOnlyCircuitData,
			CommonCircuitData:       commonCircuitData,
		}

		var builder frontend.NewBuilder = r1cs.NewBuilder
		r1csCompiled, err = frontend.Compile(ecc.BN254.ScalarField(), builder, &circuit)
		if err != nil {
			fmt.Println("error in building circuit", err)
			os.Exit(1)
		}

		fR1CS, _ := os.Create(r1csFile)
		r1csCompiled.WriteTo(fR1CS)
		fR1CS.Close()
	}

	// Get the proving and verifying key
	var pk groth16.ProvingKey
	var vk groth16.VerifyingKey
	var provingKeyFile = out + groth16ProvingKeyFile
	var verifyingKeyFile = out + groth16VerifyingKeyFile
	var verifierSolFile = out + groth16SolidityVerifierFile
	if fileExists(provingKeyFile) && fileExists(verifyingKeyFile) {
		fmt.Println("Loading proving and verifying key", time.Now())
		
		fPK, _ := os.Open(provingKeyFile)
		pkReader := bufio.NewReaderSize(fPK, fileReaderBuffSize)
		pk = groth16.NewProvingKey(ecc.BN254)
		pk.ReadFrom(pkReader)
		fPK.Close()
		
		fVK, _ := os.Open(verifyingKeyFile)
		vkReader := bufio.NewReaderSize(fVK, fileReaderBuffSize)
		vk = groth16.NewVerifyingKey(ecc.BN254)
		vk.ReadFrom(vkReader)
		fVK.Close()

	} else {
		fmt.Println("Setting up proving and verifying key", time.Now())

		pk, vk, err = groth16.Setup(r1csCompiled)
		if err != nil {
			fmt.Println(err)
			os.Exit(1)
		}

		fPK, _ := os.Create(provingKeyFile)
		if compressedKeys {
			pk.WriteTo(fPK)
		} else {
			pk.WriteRawTo(fPK)
		}
		fPK.Close()

		if vk != nil {
			fVK, _ := os.Create(verifyingKeyFile)
			if compressedKeys {
				vk.WriteTo(fVK)
			} else {
				vk.WriteRawTo(fVK)
			}
			fVK.Close()
		}

		fSolidity, _ := os.Create(verifierSolFile)
		vk.ExportSolidity(fSolidity)
		fSolidity.Close()
	}

	// Generate the witness
	fmt.Println("Generating witness", time.Now())

	var witness witness.Witness
	{
		verifierOnlyCircuitData := variables.DeserializeVerifierOnlyCircuitData(types.ReadVerifierOnlyCircuitData(in + plonky2VerifierFile))
		proofWithPis := variables.DeserializeProofWithPublicInputs(types.ReadProofWithPublicInputs(in + plonky2ProofFile))
		assignment := VerifierCircuit{
			PublicInputs:            proofWithPis.PublicInputs,
			Proof:                   proofWithPis.Proof,
			VerifierOnlyCircuitData: verifierOnlyCircuitData,
		}
		witness, _ = frontend.NewWitness(&assignment, ecc.BN254.ScalarField())
	}
	publicWitness, _ := witness.Public()

	// Generate the proof
	fmt.Println("Generating proof", time.Now())

	var proof groth16.Proof
	proof, err = groth16.Prove(r1csCompiled, pk, witness, backend.WithProverHashToFieldFunction(sha256.New()))
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	// Verify the proof
	if vk != nil {
		fmt.Println("Verifying proof", time.Now())

		err = groth16.Verify(proof, vk, publicWitness, backend.WithVerifierHashToFieldFunction(sha256.New()))
		if err != nil {
			fmt.Println(err)
			os.Exit(1)
		}
	}

	// Format the proof for the solidity verifier
	solProof := buildSolidityProof(proof, publicWitness)
	fmt.Println("Proof:", solProof.Proof)
	fmt.Println("Commitments:", solProof.Commitments)
	fmt.Println("CommitmentPok:", solProof.CommitmentPok)
	fmt.Println("Input:", solProof.Input)

    jsonProof, err := json.MarshalIndent(solProof, "", "  ")
    if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	fProof, _ := os.Create(out + groth16ProofFile)
	fProof.Write(jsonProof)
	fProof.Close()
}

func fileExists(filename string) bool {
    _, err := os.Stat(filename)
    if os.IsNotExist(err) {
        return false
    }
    return err == nil
}

func ensureDir(dirName string) error {
	err := os.MkdirAll(dirName, os.ModePerm)
	if err != nil {
		return fmt.Errorf("failed to create directory %s: %v", dirName, err)
	}
	return nil
}

func buildSolidityProof(rawProof groth16.Proof, publicWitness witness.Witness) SolidityProof {
	const fpSize = 4 * 8
	var buf bytes.Buffer
	rawProof.WriteRawTo(&buf)
	proofBytes := buf.Bytes()

	// Solidity proof (proof.Ar, proof.Bs, proof.Krs)
	var proof [8]string
	for i := 0; i < 8; i++ {
		proof[i] = fmt.Sprintf("0x%s", new(big.Int).SetBytes(proofBytes[fpSize*i : fpSize*(i+1)]).Text(16))
	}

	// Commitments and commitmentPok
	ccount := new(big.Int).SetBytes(proofBytes[fpSize*8 : fpSize*8+4])
	commitmentCount := int(ccount.Int64())

	var commitments []string = make([]string, 2*commitmentCount)
	for i := 0; i < 2*commitmentCount; i++ {
		commitments[i] = fmt.Sprintf("0x%s", new(big.Int).SetBytes(proofBytes[fpSize*8+4+i*fpSize : fpSize*8+4+(i+1)*fpSize]).Text(16))
	}

	var commitmentPok [2]string
	commitmentPok[0] = fmt.Sprintf("0x%s", new(big.Int).SetBytes(proofBytes[fpSize*8+4+2*commitmentCount*fpSize : fpSize*8+4+2*commitmentCount*fpSize+fpSize]).Text(16))
	commitmentPok[1] = fmt.Sprintf("0x%s", new(big.Int).SetBytes(proofBytes[fpSize*8+4+2*commitmentCount*fpSize+fpSize : fpSize*8+4+2*commitmentCount*fpSize+2*fpSize]).Text(16))

	// Public inputs
	w, _ := publicWitness.Vector().(fr.Vector)
	inputCount := len(w)

	var input []uint64 = make([]uint64, inputCount)
	for i := 0; i < inputCount; i++ {
		in := new(big.Int)
		w[i].BigInt(in)
		input[i] = in.Uint64()
	}

	// Build
	return SolidityProof{
		Proof: proof,
		Commitments: commitments,
		CommitmentPok: commitmentPok,
		Input: input,
    }
}

func main() {
	inputFiles := plonky2VerifierFile + ", " + plonky2CommonFile + ", " + plonky2ProofFile
	outputFiles := groth16CircuitFile + ", " + groth16ProvingKeyFile + ", " + groth16VerifyingKeyFile + ", " + groth16SolidityVerifierFile

	in := flag.String("in", "./", "path for input files [" + inputFiles + "]")
	out := flag.String("out", "./groth16/", "path for output files [" + outputFiles + "]")
	compressedKeys := flag.Bool("compressed", false, "use compressed keys")

	flag.Parse()

	if in == nil || *in == "" {
		*in = "./"
	}
	if !strings.HasSuffix(*in, "/") {
		*in += "/"
	}

	if out == nil || *out == "" {
		*out = "./groth16/"
	}
	if !strings.HasSuffix(*out, "/") {
		*out += "/"
	}

	groth16Proof(*in, *out, *compressedKeys)
}
