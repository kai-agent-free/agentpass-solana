import * as anchor from "@coral-xyz/anchor";
import { Program } from "@coral-xyz/anchor";
import { AgentpassAnchor } from "../target/types/agentpass_anchor";
import { expect } from "chai";
import { createHash } from "crypto";

describe("agentpass-anchor", () => {
  const provider = anchor.AnchorProvider.env();
  anchor.setProvider(provider);

  const program = anchor.workspace.AgentpassAnchor as Program<AgentpassAnchor>;
  const authority = provider.wallet;

  const passportId = "ap_test_abc123";

  // Derive passport PDA
  const [passportPda] = anchor.web3.PublicKey.findProgramAddressSync(
    [Buffer.from("passport"), Buffer.from(passportId)],
    program.programId
  );

  // Create a credential hash
  const credentialJson = JSON.stringify({
    type: "capability",
    issuer: "ap_issuer_xyz",
    subject: passportId,
    claim: "code-review",
    issued_at: "2026-03-30T00:00:00Z",
  });
  const credentialHash = createHash("sha256").update(credentialJson).digest();

  // Derive credential PDA
  const [credentialPda] = anchor.web3.PublicKey.findProgramAddressSync(
    [Buffer.from("credential"), passportPda.toBuffer(), credentialHash],
    program.programId
  );

  it("registers a passport", async () => {
    const tx = await program.methods
      .registerPassport(passportId)
      .accounts({
        passportAccount: passportPda,
        authority: authority.publicKey,
        systemProgram: anchor.web3.SystemProgram.programId,
      })
      .rpc();

    console.log("Register passport tx:", tx);

    const account = await program.account.passportAccount.fetch(passportPda);
    expect(account.passportId).to.equal(passportId);
    expect(account.authority.toString()).to.equal(authority.publicKey.toString());
    expect(account.credentialCount.toNumber()).to.equal(0);
    expect(account.createdAt.toNumber()).to.be.greaterThan(0);
  });

  it("fails to register duplicate passport", async () => {
    try {
      await program.methods
        .registerPassport(passportId)
        .accounts({
          passportAccount: passportPda,
          authority: authority.publicKey,
          systemProgram: anchor.web3.SystemProgram.programId,
        })
        .rpc();
      expect.fail("Should have thrown");
    } catch (err: any) {
      // Account already exists - init should fail
      expect(err.toString()).to.include("already in use");
    }
  });

  it("fails to register passport with empty ID", async () => {
    const emptyId = "";
    const [emptyPda] = anchor.web3.PublicKey.findProgramAddressSync(
      [Buffer.from("passport"), Buffer.from(emptyId)],
      program.programId
    );

    try {
      await program.methods
        .registerPassport(emptyId)
        .accounts({
          passportAccount: emptyPda,
          authority: authority.publicKey,
          systemProgram: anchor.web3.SystemProgram.programId,
        })
        .rpc();
      expect.fail("Should have thrown");
    } catch (err: any) {
      expect(err.toString()).to.include("InvalidPassportId");
    }
  });

  it("anchors a credential", async () => {
    const tx = await program.methods
      .anchorCredential(
        Array.from(credentialHash) as any,
        "ap_issuer_xyz",
        passportId,
        "capability"
      )
      .accounts({
        passportAccount: passportPda,
        credentialAnchor: credentialPda,
        authority: authority.publicKey,
        systemProgram: anchor.web3.SystemProgram.programId,
      })
      .rpc();

    console.log("Anchor credential tx:", tx);

    const credential = await program.account.credentialAnchor.fetch(credentialPda);
    expect(credential.issuer).to.equal("ap_issuer_xyz");
    expect(credential.subject).to.equal(passportId);
    expect(credential.credentialType).to.equal("capability");
    expect(credential.revoked).to.equal(false);
    expect(Buffer.from(credential.credentialHash)).to.deep.equal(credentialHash);

    // Check credential count incremented
    const passport = await program.account.passportAccount.fetch(passportPda);
    expect(passport.credentialCount.toNumber()).to.equal(1);
  });

  it("fails to anchor credential with wrong authority", async () => {
    const fakeAuthority = anchor.web3.Keypair.generate();
    const hash2 = createHash("sha256").update("fake-cred").digest();
    const [credPda2] = anchor.web3.PublicKey.findProgramAddressSync(
      [Buffer.from("credential"), passportPda.toBuffer(), hash2],
      program.programId
    );

    try {
      await program.methods
        .anchorCredential(
          Array.from(hash2) as any,
          "ap_fake",
          passportId,
          "endorsement"
        )
        .accounts({
          passportAccount: passportPda,
          credentialAnchor: credPda2,
          authority: fakeAuthority.publicKey,
          systemProgram: anchor.web3.SystemProgram.programId,
        })
        .signers([fakeAuthority])
        .rpc();
      expect.fail("Should have thrown");
    } catch (err: any) {
      // has_one constraint should fail
      expect(err.toString()).to.include("ConstraintHasOne");
    }
  });

  it("revokes a credential", async () => {
    const tx = await program.methods
      .revokeCredential()
      .accounts({
        passportAccount: passportPda,
        credentialAnchor: credentialPda,
        authority: authority.publicKey,
      })
      .rpc();

    console.log("Revoke credential tx:", tx);

    const credential = await program.account.credentialAnchor.fetch(credentialPda);
    expect(credential.revoked).to.equal(true);
  });

  it("fails to revoke already revoked credential", async () => {
    try {
      await program.methods
        .revokeCredential()
        .accounts({
          passportAccount: passportPda,
          credentialAnchor: credentialPda,
          authority: authority.publicKey,
        })
        .rpc();
      expect.fail("Should have thrown");
    } catch (err: any) {
      expect(err.toString()).to.include("AlreadyRevoked");
    }
  });

  it("anchors multiple credentials", async () => {
    for (let i = 0; i < 3; i++) {
      const hash = createHash("sha256").update(`cred-${i}`).digest();
      const [pda] = anchor.web3.PublicKey.findProgramAddressSync(
        [Buffer.from("credential"), passportPda.toBuffer(), hash],
        program.programId
      );

      await program.methods
        .anchorCredential(
          Array.from(hash) as any,
          `ap_issuer_${i}`,
          passportId,
          "endorsement"
        )
        .accounts({
          passportAccount: passportPda,
          credentialAnchor: pda,
          authority: authority.publicKey,
          systemProgram: anchor.web3.SystemProgram.programId,
        })
        .rpc();
    }

    const passport = await program.account.passportAccount.fetch(passportPda);
    // 1 original + 3 new = 4
    expect(passport.credentialCount.toNumber()).to.equal(4);
  });
});
