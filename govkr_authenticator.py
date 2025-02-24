import binascii, pypinksign

from pyasn1.codec.der import decoder as der_decoder
from pyasn1.codec.der import encoder as der_encoder
from pyasn1.type.univ import Sequence, OctetString

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization

from govkr_client import Gov24_Client

class Gov24_Authenticator:
    def __init__(self, server_privkey_path: str, server_privkey_password: str):
        """
        :param server_privkey_path: 서버 개인키 파일 경로
        :param server_privkey_password: 서버 개인키 비밀번호
        """

        self.server_key = serialization.load_pem_private_key(
            open(server_privkey_path, "rb").read(), 
            password=server_privkey_password.encode("utf-8")
        )

    def parse_pkcs7_signed_data(self, pkcs7_der: bytes) -> tuple[bytes, Sequence, bytes]:
        """
        PKCS#7 서명 데이터에서 다음을 추출합니다:
        1) 원본 데이터 (original_data)
        2) 클라이언트 인증서 (cert_seq)
        3) 서명값 (signature_value)
        """

        # 최상위 SEQUENCE 디코딩
        top_seq, _ = der_decoder.decode(pkcs7_der)

        # PKCS#7 SignedData 추출
        signed_data_seq = top_seq[1]

        # SignedData 내부 필드:
        #   [0] version
        #   [1] digestAlgorithms
        #   [2] contentInfo
        #   [3] certificates
        #   [4] signerInfos

        content_info = signed_data_seq[2]  # EncapsulatedContentInfo (SEQUENCE)
        certificates = signed_data_seq[3]  # 인증서 목록
        signer_infos = signed_data_seq[4]  # 서명 정보

        # 원본 데이터 추출
        # contentInfo[1]이 OctetString이면 원본 데이터로 사용
        if len(content_info) >= 2 and isinstance(content_info[1], OctetString):
            original_data = content_info[1].asOctets()
        else:
            original_data = b""  # 원본 데이터가 없을 경우

        # 인증서 정보 추출
        # certificates[0], 첫 번째 인증서 (SEQUENCE) 가져오기
        cert_seq = certificates[0]

        # 서명값 추출
        # signerInfos[0][4] = encryptedDigest (OctetString) 형태의 서명값
        signer_info_seq = signer_infos[0]
        signature_value = signer_info_seq[4].asOctets()

        return original_data, cert_seq, signature_value

    def extract_public_key_from_parsed_cert(self, cert_seq: Sequence) -> rsa.RSAPublicKey:
        """
        파싱된 인증서(Sequence)로부터 RSA 공개키(n, e)를 추출하여
        cryptography의 RSAPublicKey 형태로 반환합니다.
        """

        # 인증서의 주요 구조 (X.509):
        # cert_seq 구조:
        #   field-0 = 버전 (INTEGER)
        #   field-1 = 일련번호 (INTEGER)
        #   field-2 = 서명 알고리즘 정보 (SEQUENCE)
        #   field-3 = 발급자 정보 (SEQUENCE)
        #   field-4 = 유효기간 (SEQUENCE)
        #   field-5 = 주체(사용자) 정보 (SEQUENCE)
        #   field-6 = subjectPublicKeyInfo (SEQUENCE)  <-- 공개키 정보
        #       ├── field-0 = 알고리즘 식별자 (SEQUENCE)
        #       │        ├── OID (1.2.840.113549.1.1.1) → RSA
        #       │        └── 추가 매개변수 (NULL)
        #       └── field-1 = BIT STRING (RSAPublicKey :: SEQUENCE { n, e })
        #   field-7 = 확장 필드 (SEQUENCE)

        # subjectPublicKeyInfo 가져오기
        spki = cert_seq[6]  # 공개키 정보가 저장된 부분

        # 공개키 데이터는 BIT STRING으로 감싸져 있음
        pubkey_bitstring = spki[1]
        if hasattr(pubkey_bitstring, "asOctets"):
            # BIT STRING에서 바이너리 데이터를 추출
            pubkey_inner = pubkey_bitstring.asOctets()
        else:
            # BIT STRING이 예상과 다를 경우, DER 인코딩을 이용해 추출
            pubkey_inner = der_encoder.encode(pubkey_bitstring)

        # BIT STRING 내부의 RSAPublicKey SEQUENCE를 디코딩
        pubseq, _ = der_decoder.decode(pubkey_inner)

        # RSAPublicKey 구조:
        #   field-0 = 모듈러스(n) (INTEGER)
        #   field-1 = 공개 지수(e) (INTEGER)
        n = int(pubseq[0])  # RSA 모듈러스
        e = int(pubseq[1])  # 공개 지수

        # RSAPublicKey 객체 생성
        pub_numbers = rsa.RSAPublicNumbers(e=e, n=n)
        public_key = pub_numbers.public_key(backend=default_backend())

        return public_key

    def verify_signature(self, original_data: bytes, public_key: rsa.RSAPublicKey, signature_value: bytes) -> bool:
        """
        RSA-PKCS1v15 + SHA256 조합을 사용하여 서명값을 검증합니다.
        """

        try:
            public_key.verify(
                signature_value,
                original_data,
                padding.PKCS1v15(),
                hashes.SHA256()
            )
            return True
        except Exception as e:
            print(f"서명 검증에 실패했습니다. : {e}")
            return False

    def decrypt_vid_msg(self, vid_msg_hex: str) -> bytes:
        """
        VID 메시지를 복호화합니다.
        1) 서버 RSA 개인키를 사용해, VID 메시지에서 추출한 대칭키(enc_symkey) 복호화
        2) 복호화된 SEED 키로 나머지 데이터(seed_encrypted)를 SEED-CBC 방식 복호화
        3) 복호화된 데이터에서 클라이언트 개인키 고유값(random_num) 추출
        """

        vid_bytes = binascii.unhexlify(vid_msg_hex)

        RSA_KEY_SIZE = 256

        # VID 메시지 구조:
        #   [0:RSA_KEY_SIZE] => 서버 RSA로 암호화된 대칭키 (enc_symkey)
        #   [RSA_KEY_SIZE:]  => SEED-CBC 암호화된 실제 데이터 (seed_encrypted)
        enc_symkey = vid_bytes[:RSA_KEY_SIZE]
        seed_encrypted = vid_bytes[RSA_KEY_SIZE:]

        # RSA 복호화 → 대칭키
        sym_key = self.server_key.decrypt(
            enc_symkey,
            padding.PKCS1v15()
        )

        # SEED-CBC 복호화 (IV=16바이트 0x00)
        # 대칭키(sym_key)로 암호화된 데이터를 복호화
        der_data = pypinksign.seed_cbc_128_decrypt(sym_key, seed_encrypted, iv=b"\x00" * 16)

        # 4) ASN.1 파싱 ( Sequence { field-0 (???), field-1 (BIT STRING) )
        seq, _ = der_decoder.decode(der_data)

        # BIT STRING 데이터 추출, 정수로 변환 후 바이트 변환
        int_val = int(seq[1])
        random_num = int_val.to_bytes((int_val.bit_length() + 7) // 8, byteorder="big")

        return random_num

    def authenticate(self, signed_hex: str, vid_msg_hex: str):
        """
        정부24 서버의 로그인 인증 절차 구현체입니다.
        """
        
        pkcs7_der = binascii.unhexlify(signed_hex)
        original_data, cert_seq, signature_value = self.parse_pkcs7_signed_data(pkcs7_der)

        user_public_key = self.extract_public_key_from_parsed_cert(cert_seq)

        if not self.verify_signature(original_data, user_public_key, signature_value):
            return False
    
        print(f"[Server] 서명 검증 성공! original_data = {original_data}")

        random_num = self.decrypt_vid_msg(vid_msg_hex)

        print(f"[Server] VID randomNum = {random_num.hex()}")

        # 클라이언트의 공개 인증서 정보를 활용해 DB/세션에 저장된 random_num 혹은 vid_msg의 nonce 여부 비교
        # 동일/무결하다면 사용자가 실제 개인키 소유자임을 확인
        # 서명 검증만으로도 개인키 소유 사실을 추측할 수 있으나 중간자 공격 대응을 위해 vid_msg를 활용합니다.
        # 해당 시뮬레이션에선 구현하지 않았습니다.
        is_vid_msg_nonce_valid = True # 간단한 bool 값으로 대체

        if is_vid_msg_nonce_valid:
            return True
        else:
            return False


def test_auth():
    """
    [서버 시뮬레이션]

    가정:
    - 실제로는 'POST' 요청 등을 통해 signed_hex, vid_msg_hex 등을 수신
    - 여기서는 Gov24_Client를 통해 임의의 테스트 시나리오를 시연
    """

    password = input("인증서의 비밀번호를 입력하세요: ")

    client = Gov24_Client(
        sign_cert_path="./인증서/signCert.der",
        sign_pri_path="./인증서/signPri.key",
        sign_pri_password=password,
        encryption_cert_path="./테스트_인증서/test.der"
    )

    signed_hex = client.get_signed_hex()
    vid_msg_hex = client._generate_vid_msg(client.signer._rand_num.asOctets())

    server = Gov24_Authenticator(
        server_privkey_path="./테스트_인증서/test.pem",
        server_privkey_password = "q1w2e3"
    )

    if server.authenticate(signed_hex, vid_msg_hex):
        print("[Server] 최종 검증 완료 - 로그인 허용!")
    else:
        print("[Server] 서명 검증 실패 - 로그인 거부")


if __name__ == "__main__":
    test_auth()