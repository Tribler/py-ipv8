"""
Copyright (c) 2016, Maarten Everts
All rights reserved.

This source code has been ported from https://github.com/privacybydesign/gabi
The authors of this file are not -in any way- affiliated with the original authors or organizations.
"""
from __future__ import annotations

import random
import time

from .....attestation.wallet.irmaexact.gabi.attributes import make_attribute_list
from .....attestation.wallet.irmaexact.gabi.builder import (
    BuildDistributedProofList,
    BuildProofList,
    Challenge,
    CredentialBuilder,
    IssueCommitmentMessage,
    Issuer,
    Verify,
)
from .....attestation.wallet.irmaexact.gabi.credential import Credential
from .....attestation.wallet.irmaexact.gabi.keys import DefaultSystemParameters, PrivateKey, PublicKey, SignMessageBlock
from .....attestation.wallet.irmaexact.gabi.proofs import ProofP, ProofPCommitment, createChallenge
from .....attestation.wallet.primitives.value import FP2Value
from ....base import TestBase

# ruff: noqa: N806


class TestCredential(TestBase):
    """
    Tests related to IRMA credentials.
    """

    def setUp(self) -> None:
        """
        Set up proof constants.
        """
        super().setUp()
        self.testAttributes1 = [1, 2, 3, 4]
        self.testAttributes2 = [5, 6, 7, 8]

        p = 10436034022637868273483137633548989700482895839559909621411910579140541345632481969613724849214412062500244238926015929148144084368427474551770487566048119
        q = 9204968012315139729618449685392284928468933831570080795536662422367142181432679739143882888540883909887054345986640656981843559062844656131133512640733759
        n = 96063359353814070257464989369098573470645843347358957127875426328487326540633303185702306359400766259130239226832166456957259123554826741975265634464478609571816663003684533868318795865194004795637221226902067194633407757767792795252414073029114153019362701793292862118990912516058858923030408920700061749321
        S = 68460510129747727135744503403370273952956360997532594630007762045745171031173231339034881007977792852962667675924510408558639859602742661846943843432940752427075903037429735029814040501385798095836297700111333573975220392538916785564158079116348699773855815825029476864341585033111676283214405517983188761136
        Z = 44579327840225837958738167571392618381868336415293109834301264408385784355849790902532728798897199236650711385876328647206143271336410651651791998475869027595051047904885044274040212624547595999947339956165755500019260290516022753290814461070607850420459840370288988976468437318992206695361417725670417150636
        R = [
            75350858539899247205099195870657569095662997908054835686827949842616918065279527697469302927032348256512990413925385972530386004430200361722733856287145745926519366823425418198189091190950415327471076288381822950611094023093577973125683837586451857056904547886289627214081538422503416179373023552964235386251,
            16493273636283143082718769278943934592373185321248797185217530224336539646051357956879850630049668377952487166494198481474513387080523771033539152347804895674103957881435528189990601782516572803731501616717599698546778915053348741763191226960285553875185038507959763576845070849066881303186850782357485430766,
            13291821743359694134120958420057403279203178581231329375341327975072292378295782785938004910295078955941500173834360776477803543971319031484244018438746973179992753654070994560440903251579649890648424366061116003693414594252721504213975050604848134539324290387019471337306533127861703270017452296444985692840,
            86332479314886130384736453625287798589955409703988059270766965934046079318379171635950761546707334446554224830120982622431968575935564538920183267389540869023066259053290969633312602549379541830869908306681500988364676409365226731817777230916908909465129739617379202974851959354453994729819170838277127986187,
            68324072803453545276056785581824677993048307928855083683600441649711633245772441948750253858697288489650767258385115035336890900077233825843691912005645623751469455288422721175655533702255940160761555155932357171848703103682096382578327888079229101354304202688749783292577993444026613580092677609916964914513,
            65082646756773276491139955747051924146096222587013375084161255582716233287172212541454173762000144048198663356249316446342046266181487801411025319914616581971563024493732489885161913779988624732795125008562587549337253757085766106881836850538709151996387829026336509064994632876911986826959512297657067426387
        ]
        self.testPubK = PublicKey(n, Z, S, R, 0, time.time() + 365 * 24 * 3600)
        self.testPrivK = PrivateKey(p, q, 0, time.time() + 365 * 24 * 3600)

        p = 12511561644521105216249960315425509848310543851123625148071038103672749250653050780946327920540373585150518830678888836864183842100121288018131086700947919
        q = 13175754961224278923898419496296790582860213842149399404614891067426616055648139811854869087421318470521236911637912285993998784296429335994419545592486183
        n = 164849270410462350104130325681247905590883554049096338805080434441472785625514686982133223499269392762578795730418568510961568211704176723141852210985181059718962898851826265731600544499072072429389241617421101776748772563983535569756524904424870652659455911012103327708213798899264261222168033763550010103177
        S = 95431387101397795194125116418957121488151703839429468857058760824105489778492929250965841783742048628875926892511288385484169300700205687919208898288594042075246841706909674758503593474606503299796011177189518412713004451163324915669592252022175131604797186534801966982736645522331999047305414834481507220892
        Z = 85612209073231549357971504917706448448632620481242156140921956689865243071517333286408980597347754869291449755693386875207418733579434926868804114639149514414312088911027338251870409643059636340634892197874721564672349336579075665489514404442681614964231517891268285775435774878821304200809336437001672124945
        R = [
            15948796959221892486955992453179199515496923441128830967123361439118018661581037984810048354811434050038778558011395590650011565629310700360843433067202313291361609843998531962373969946197182940391414711398289105131565252299185121868561402842968555939684308560329951491463967030905495360286851791764439565922,
            119523438901119086528333705353116973341573129722743063979885442255495816390473126070276442804547475203517104656193873407665058481273192071865721910619056848142740067272069428460724210705091048104466624895000063564223095487133194907203681789863578060886235105842841954519189942453426975057803871974937309502784,
            21036812778930907905009726679774009067486097699134635274413938052367886222555608567065065339702690960558290977766511663461460906408225144877806673612081001465755091058944847078216758263034300782760502281865270151054157854728772298542643419836244547728225955304279190350362963560596454003412543292789187837679,
            2507221674373339204944916721547102290807064604358409729371715856726643784893285066715992395214052930640947278288383410209092118436778149456628267900567208684458410552361708506911626161349456189054709967676518205745736652492505957876189855916223094854626710186459345996698113370306994139940441752005221653088,
            43215325590379490852400435325847836613513274803460964568083232110934910151335113918829588414147781676586145312074043749201037447486205927144941119404243266454032858201713735324770837218773739346063812751896736791478531103409536739098007890723770126159814845238386299865793353073058783010002988453373168625327,
            61146634020942775692657595021461289090915429142715194304483397998858712705680675945417056124974172620475325240482216550923967273908399017396442709297466408094303826941548068001214817725191465207971123378222070812822903173820970991987799984521470178624084174451047081964996323127069438975310975798326710264763
        ]
        self.testPubK1 = PublicKey(n, Z, S, R, 0, time.time() + 365 * 24 * 3600)
        self.testPrivK1 = PrivateKey(p, q, 0, time.time() + 365 * 24 * 3600)

        p = 11899204220405157066705854076362480104861239101931883074217284817546620402667365757487512145720112988257938861512783018148367540266552183843422556696835959
        q = 11687675946826056427944301889720810769697676393649416932482597289652868791085152984663910808816076612347241543876183667586150260004323007396424045765933627
        n = 139074042953200450756577573716087081093125755047959835310375736112120174400606581560965321655328552305330880412762069205250416578144697608952814011140599345836848582980530546248138864212612840364874312923816166397038873282769982501212640794354680085233677961149767121970163329979736254573701512654860500893293
        S = 126829853005972541969086001260986453668465797381061677444000682968013144068393822597398725937194773101762625079278987532636583109409344117202136151661601603097793537754186056937000748076167489862365768508194908399597522777250699581364596246205795577663373872577816687658275462617741670486719685398698263686551
        Z = 42734451137499583379659313067721582376262445005019898840924212896341861721344880887076647548954065511016613532399873561753770596699950716884806217151189571670373798409647535613026097425988280287210414508240665780830389936353108210951728065700426436951835936702999674654289936428229982569295227091726810208504
        R = [
            40338259065130185314739658157310048192093670364817714952600609624607192408306024366086231626356707587756324374416236635377699775899652135471760526981946419799164489776538365542337621218846077191008645978143565824845696569002709540904092145615635620069766477253299607733404658708555482236387943774145644107155,
            87294590926764077882765166008319250454824581316986036240948880310176122397314769805046534571305547053810590771663913726538715272940723444205499052940110064720613691982665763438729000435763267929115086526907175748438671858290067669579138779857489538782552512452684382063115068635634905118784884820252032788713,
            45112630188085238903069069511798663932075329935779132383847263380203067284915894010441781813845184965705336439320602592823045182968796600558189004025038858823202813711551231906042036283775342496224178435309129468488081668058550719904823188068692199073681725733882486184478432125414991289211704253384344158081,
            22895199267295669971377907000498707372807373558129284002593860052803834778891828018872532360982520545310813792866731358720045880773782974790652802346358667674975135735260730170180413669755483849990358724482246391921757338735789576941697731958222822227522297243574534946426308507662162995899206568536028623103,
            29442357694189149206874997834969163436044466589167060785051742894686201256234721711106548932718033481872195748036017185452480637488189438942261880419540814690300046143608677755570098259230237537965383960964005848716674912279997266193234061274749285289871273401669268876576539473354504176111056568584915827297,
            131901907144475345605474419271525166840628320727233669347338800265775060322235098813990701559838451432946945231275304351611643638306679131070017823266011946014245927069041536778330134744287743396547932833493856762058626556853615297319468923040156688227503880614709468161168272362825615977596973869772839600546
        ]
        self.testPubK2 = PublicKey(n, Z, S, R, 0, time.time() + 365 * 24 * 3600)
        self.testPrivK2 = PrivateKey(p, q, 0, time.time() + 365 * 24 * 3600)

    def _createCredential(self, context: int, secret: int, issuer: Issuer) -> Credential | None:  # noqa: N802
        """
        Have an issuer construct a credential for the given context and secret.
        """
        keylength = 1024
        nonce1 = random.randint(0, DefaultSystemParameters[keylength].Lstatzk)
        nonce2 = random.randint(0, DefaultSystemParameters[keylength].Lstatzk)
        cb = CredentialBuilder(issuer.Pk, context, secret, nonce2)
        commitMsg = cb.CommitToSecretAndProve(nonce1)
        ism = issuer.IssueSignature(commitMsg.U, self.testAttributes1, nonce2)
        return cb.ConstructCredential(ism, self.testAttributes1)

    def test_show_proof(self) -> None:
        """
        Test showing a partial proof.
        """
        signature = SignMessageBlock(self.testPrivK, self.testPubK, self.testAttributes1)

        cred = Credential(self.testPubK, self.testAttributes1, signature)
        disclosed = [1, 2]

        context = random.randint(0, self.testPubK.Params.Lh)
        nonce1 = random.randint(0, self.testPubK.Params.Lstatzk)

        proof = cred.CreateDisclosureProof(disclosed, context, nonce1)

        self.assertTrue(proof.Verify(self.testPubK, context, nonce1, False))

    def test_construct_credential(self) -> None:
        """
        Test constructing a credential.
        """
        context = random.randint(0, 1 << (self.testPubK.Params.Lh - 1))
        nonce1 = random.randint(0, 1 << (self.testPubK.Params.Lstatzk - 1))
        nonce2 = random.randint(0, 1 << (self.testPubK.Params.Lstatzk - 1))
        secret = random.randint(0, 1 << (self.testPubK.Params.Lm - 1))

        cb = CredentialBuilder(self.testPubK1, context, secret, nonce2)
        commit_msg = cb.CommitToSecretAndProve(nonce1)

        issuer = Issuer(self.testPrivK1, self.testPubK1, context)
        msg = issuer.IssueSignature(commit_msg.U, self.testAttributes1, nonce2)

        self.assertIsNotNone(cb.ConstructCredential(msg, self.testAttributes1))

    def test_construct_credential_challenge(self) -> None:
        """
        Test constructing a credential with Challenge.
        """
        context = random.randint(0, 1 << (self.testPubK.Params.Lh - 1))
        nonce1 = random.randint(0, 1 << (self.testPubK.Params.Lstatzk - 1))
        nonce2 = random.randint(0, 1 << (self.testPubK.Params.Lstatzk - 1))
        secret = random.randint(0, 1 << (self.testPubK.Params.Lm - 1))

        cb = CredentialBuilder(self.testPubK1, context, secret, nonce2)
        challenge = Challenge([cb], context, nonce1, False)
        proofs = BuildDistributedProofList([cb], challenge, [])
        commit_msg = IssueCommitmentMessage(None, proofs, nonce1)

        self.assertTrue(Verify(commit_msg.Proofs, [self.testPubK1], context, nonce1, False))

        issuer = Issuer(self.testPrivK1, self.testPubK1, context)
        msg = issuer.IssueSignature(commit_msg.Proofs[0].U, self.testAttributes1, nonce2)

        self.assertIsNotNone(cb.ConstructCredential(msg, self.testAttributes1))

    def test_construct_credential_challenge_pcommit(self) -> None:
        """
        Test constructing a credential with Challenge and PCommit.
        """
        context = random.randint(0, 1 << (self.testPubK.Params.Lh - 1))
        nonce1 = random.randint(0, 1 << (self.testPubK.Params.Lstatzk - 1))
        nonce2 = random.randint(0, 1 << (self.testPubK.Params.Lstatzk - 1))
        secret = random.randint(0, 1 << (self.testPubK.Params.Lm - 1))
        issuer = Issuer(self.testPrivK1, self.testPubK1, context)
        cr = {
            'keyCounter': 0,
            'credential': 'test.credential',
            'validity': int(time.time()) + 60000,
            'attributes': {
                "test1": "value1",
                "test2": "value2"
            }
        }

        s = 1234
        s_randomizer = 5678
        pcommit = ProofPCommitment(FP2Value(issuer.Pk.N, issuer.Pk.R[0]).intpow(s).a,
                                   FP2Value(issuer.Pk.N, issuer.Pk.R[0]).intpow(s_randomizer).a)

        cb = CredentialBuilder(self.testPubK1, context, secret, nonce2)
        cb.MergeProofPCommitment(pcommit)
        challenge = Challenge([cb], context, nonce1, False)
        proof_p = ProofP(pcommit.P, challenge, s_randomizer + challenge * s)

        proofs = BuildDistributedProofList([cb], challenge, [])
        for p in proofs:
            p.MergeProofP(proof_p, self.testPubK1)
        commit_msg = IssueCommitmentMessage(None, proofs, nonce1)

        self.assertTrue(Verify(commit_msg.Proofs, [self.testPubK1], context, nonce1, False))
        self.assertEqual(1, len(commit_msg.Proofs))

        attr_list, signing_date = make_attribute_list(cr)
        msg = issuer.IssueSignature(commit_msg.Proofs[0].U, attr_list, nonce2)
        credential = cb.ConstructCredential(msg, attr_list)
        self.assertIsNotNone(credential)

        # Verifier side
        challenge_verif = random.randint(0, issuer.Pk.N)

        # Prover side
        builder = credential.CreateDisclosureProofBuilder(list(range(1, len(attr_list) + 1)))
        builder.MergeProofPCommitment(pcommit)
        commit_randomizer = random.randint(0, 1 << (self.testPubK.Params.LmCommit - 1))
        A, Z = builder.Commit(commit_randomizer)
        p = builder.CreateProof(challenge)
        p.MergeProofP(proof_p, issuer.Pk)

        # Respond to challenge
        secondaryChallenge = createChallenge(challenge_verif, challenge_verif, [A, Z], False)

        # Commit to p.C, p.A, p.EResponse, p.VResponse, p.AResponses
        # Blank out attributes before sharing
        p.ADisclosed = {}  # p now resembles ProofD on Verifier side

        # Verifier side
        reconstructed_attr_list, _ = make_attribute_list(cr)
        reconstructed_attr_map = {}
        for i in range(len(attr_list)):
            reconstructed_attr_map[i + 1] = attr_list[i]
        p.ADisclosed = reconstructed_attr_map
        Ap, Zp = p.ChallengeContribution(issuer.Pk)
        p.C = secondaryChallenge
        reconstructed_challenge = createChallenge(challenge_verif, challenge_verif, [Ap, Zp], False)
        self.assertTrue(p.VerifyWithChallenge(issuer.Pk, reconstructed_challenge))

    def test_show_proof_list(self) -> None:
        """
        Test showing a list of proofs.
        """
        context = random.randint(0, self.testPubK.Params.Lh)
        nonce1 = random.randint(0, self.testPubK.Params.Lstatzk)
        secret = random.randint(0, self.testPubK.Params.Lm)

        issuer1 = Issuer(self.testPrivK1, self.testPubK1, context)
        cred1 = self._createCredential(context, secret, issuer1)

        issuer2 = Issuer(self.testPrivK2, self.testPubK2, context)
        cred2 = self._createCredential(context, secret, issuer2)

        builders = [cred1.CreateDisclosureProofBuilder([1, 2]), cred2.CreateDisclosureProofBuilder([1, 3])]
        prooflist = BuildProofList(builders, context, nonce1, False)

        self.assertTrue(Verify(prooflist, [issuer1.Pk, issuer2.Pk], context, nonce1, False))

    def test_issue_and_show(self) -> None:
        """
        Test the full stack of issuance and showing.
        """
        context = random.randint(0, self.testPubK.Params.Lh)
        nonce1 = random.randint(0, self.testPubK.Params.Lstatzk)
        nonce2 = random.randint(0, self.testPubK.Params.Lstatzk)
        secret = random.randint(0, self.testPubK.Params.Lm)

        cb1 = CredentialBuilder(self.testPubK, context, secret, nonce2)
        commitMsg = cb1.CommitToSecretAndProve(nonce1)

        issuer1 = Issuer(self.testPrivK, self.testPubK, context)
        ism = issuer1.IssueSignature(commitMsg.U, self.testAttributes1, nonce2)

        cred1 = cb1.ConstructCredential(ism, self.testAttributes1)

        cb2 = CredentialBuilder(self.testPubK, context, secret, nonce2)
        issuer2 = Issuer(self.testPrivK, self.testPubK, context)

        builders = [cred1.CreateDisclosureProofBuilder([1, 2]), cb2]
        prooflist = BuildProofList(builders, context, nonce1, False)

        commitMsg2 = cb2.CreateIssueCommitmentMessage(prooflist)

        self.assertTrue(Verify(commitMsg2.Proofs, [self.testPubK, self.testPubK], context, nonce1, False))

        msg = issuer2.IssueSignature(commitMsg2.U, self.testAttributes1, nonce2)
        cred2 = cb2.ConstructCredential(msg, self.testAttributes1)

        nonce1s = random.randint(0, self.testPubK.Params.Lstatzk)
        disclosedAttributes = [1, 3]
        proof = cred2.CreateDisclosureProof(disclosedAttributes, context, nonce1s)

        self.assertTrue(proof.Verify(self.testPubK, context, nonce1s, False))

    def test_issue_show_random(self) -> None:
        """
        Test the full stack of issuance, deriving and showing.
        """
        keylength = 1024
        context = random.randint(0, DefaultSystemParameters[keylength].Lh)
        secret = random.randint(0, DefaultSystemParameters[keylength].Lm)
        nonce2 = random.randint(0, DefaultSystemParameters[keylength].Lstatzk)

        issuer1 = Issuer(self.testPrivK1, self.testPubK1, context)
        cred1 = self._createCredential(context, secret, issuer1)

        issuer2 = Issuer(self.testPrivK2, self.testPubK2, context)
        cb2 = CredentialBuilder(issuer2.Pk, context, secret, nonce2)

        nonce1 = random.randint(0, DefaultSystemParameters[keylength].Lstatzk)
        builders = [cred1.CreateDisclosureProofBuilder([1, 2]), cb2]
        prooflist = BuildProofList(builders, context, nonce1, False)

        commitMsg = cb2.CreateIssueCommitmentMessage(prooflist)

        self.assertTrue(Verify(commitMsg.Proofs, [issuer1.Pk, issuer2.Pk], context, nonce1, False))

        msg = issuer2.IssueSignature(commitMsg.U, self.testAttributes2, nonce2)
        cred2 = cb2.ConstructCredential(msg, self.testAttributes2)

        nonce1s = random.randint(0, issuer2.Pk.Params.Lstatzk)
        disclosedAttributes = [1, 3]
        proof = cred2.CreateDisclosureProof(disclosedAttributes, context, nonce1s)

        self.assertTrue(proof.Verify(issuer2.Pk, context, nonce1s, False))

    def test_big_attribute(self) -> None:
        """
        Test if a big attribute value still works.
        """
        attrs = [1, 2,
                 139074042953200450756577573716087081093125755047959835310375736112120174400606581560965321655328552305330880412762069205250416578144697608952814011140599345836848582980530546248138864212612840364874312923816166397038873282769982501212640794354680085233677961149767121970163329979736254573701512654860500893293]
        signature = SignMessageBlock(self.testPrivK, self.testPubK, attrs)
        cred = Credential(self.testPubK, attrs, signature)
        self.assertTrue(signature.Verify(self.testPubK, attrs))

        context = random.randint(0, self.testPubK.Params.Lh)
        nonce1 = random.randint(0, self.testPubK.Params.Lstatzk)

        proof = cred.CreateDisclosureProof([1], context, nonce1)
        self.assertTrue(proof.Verify(self.testPubK, context, nonce1, False))

        proof = cred.CreateDisclosureProof([2], context, nonce1)
        self.assertTrue(proof.Verify(self.testPubK, context, nonce1, False))
