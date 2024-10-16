import {
  ZkProgram,
  Field,
  DynamicProof,
  Proof,
  VerificationKey,
  Undefined,
  verify,
  assert,
  Void,
} from 'o1js';

const guessNumber = ZkProgram({
  name: 'guess-number',
  publicInput: Field,

  methods: {
    guess: {
      privateInputs: [Field],
      async method(expect: Field, guess: Field) {
        guess.assertEquals(guess);
      },
    },
  },
});

class DynamicGuessNumberProof extends DynamicProof<Field, Void> {
  static publicInputType = Field;
  static publicOutputType = Void;
  static maxProofsVerified = 0 as const;
}

const squareRoot = ZkProgram({
  name: 'square-root',
  publicInput: Field,

  methods: {
    check: {
      privateInputs: [Field],
      async method(target: Field, potentialRoot: Field) {
        target.assertEquals(potentialRoot.mul(potentialRoot));
      },
    },
  },
});

class DynamicSquareRootProof extends DynamicProof<Field, Void> {
  static publicInputType = Field;
  static publicOutputType = Void;
  static maxProofsVerified = 0 as const;
}

const guessNumberRoot = ZkProgram({
  name: 'guess-number-root',

  methods: {
    guessRoot: {
      privateInputs: [
        VerificationKey,
        DynamicGuessNumberProof,
        VerificationKey,
        DynamicSquareRootProof,
      ],
      async method(
        vkGuess: VerificationKey,
        proofGuess: DynamicGuessNumberProof,
        vkSqrt: VerificationKey,
        proofSqrt: DynamicSquareRootProof
      ) {
        // Field(
        //   17092364826726222365113483755954177665416289346523529826780240501733802974489n
        // ).assertEquals(vkGuess.hash);
        // Field(
        //   7366579521807958688380708523943536275961244156544953379731585537782625645675n
        // ).assertEquals(vkSqrt.hash);
        proofGuess.verify(vkGuess);
        proofSqrt.verify(vkSqrt);
        proofGuess.publicInput.assertEquals(proofSqrt.publicInput);
        proofGuess.publicInput.assertEquals(Field(144));
      },
    },
  },
});

console.log('Compiling...');
const guessVk = (await guessNumber.compile()).verificationKey;
const squareRootVk = (await squareRoot.compile()).verificationKey;
await guessNumberRoot.compile();
// console.log(guessVk.hash.toBigInt());
// console.log(squareRootVk.hash.toBigInt());

const proofGuess = await guessNumber.guess(Field(144), Field(144));
const proofRoot = await squareRoot.check(Field(144), Field(12));

const dynProofGuess = DynamicGuessNumberProof.fromProof(proofGuess);
const dynProofRoot = DynamicSquareRootProof.fromProof(proofRoot);

const proofGuessRoot = await guessNumberRoot.guessRoot(
  guessVk,
  dynProofGuess,
  squareRootVk,
  dynProofRoot
);

let ok = await guessNumberRoot.verify(proofGuessRoot);
console.log('ok?', ok);
