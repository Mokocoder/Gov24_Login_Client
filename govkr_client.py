import os, re, base64, urllib.parse, requests, pypinksign
from pyasn1.type import univ, char
from pyasn1.codec.der import encoder as der_encoder

class LoginError(Exception):
    """로그인 오류 발생 시 사용되는 예외 클래스"""

    pass


class Gov24_Client:
    def __init__(self, sign_cert_path: str, sign_pri_path: str, sign_pri_password: str, encryption_cert_path: str = None):
        """
        :param sign_cert_path: 서명용 공개 인증서 경로
        :param sign_pri_path: 서명용 개인키 파일 경로
        :param sign_pri_password: 서명용 개인키 비밀번호
        :param encryption_cert_path: 대칭키 암호화를 위한 서버 인증서 경로
        """

        self.session = requests.Session()
        self.sign_cert_path = sign_cert_path
        self.sign_pri_path = sign_pri_path
        self.sign_pri_password = sign_pri_password
        self.encryption_cert_path = encryption_cert_path

        self.signer = pypinksign.PinkSign(
            pubkey_path=self.sign_cert_path,
            prikey_path=self.sign_pri_path,
            prikey_password=self.sign_pri_password.encode('utf-8')
        )

    def _generate_vid_msg(self, random_num: bytes) -> str:
        """
        ASN.1 DER 구조를 생성한 후 SEED/CBC 암호화하고,
        대칭키를 인증서의 공개키(RSAES-PKCS1-V1_5)로 암호화하여 두 암호문을 결합합니다.
        """

        symmetric_key = os.urandom(16)
        
        iv = b'\x00' * 16

        # ASN.1 DER 구조 생성: Sequence { PrintableString "", BIT STRING (random_num) }
        seq = univ.Sequence()
        seq.setComponentByPosition(0, char.PrintableString(''))
        seq.setComponentByPosition(1, univ.BitString.fromOctetString(random_num))
        der_data = der_encoder.encode(seq)

        # SEED/CBC 암호화
        seed_encrypted = pypinksign.seed_cbc_128_encrypt(symmetric_key, der_data, iv)

        # 인증서의 공개키로 대칭키 암호화 (RSAES-PKCS1-V1_5)
        cert_kwargs = {'pubkey_path': self.encryption_cert_path} if self.encryption_cert_path else {'pubkey_data': self.get_svr_cert()}
        encrypted_sym_key = pypinksign.PinkSign(**cert_kwargs).encrypt(symmetric_key)

        # 두 암호문 결합 후 hex 문자열로 반환
        final_bytes = encrypted_sym_key + seed_encrypted
        return final_bytes.hex()
    
    def get_svr_cert(self) -> bytes:
        """
        정부24 사이트에서 서버 인증서를 받아옵니다.
        """

        html_content = requests.get('https://www.gov.kr/nlogin/?Mcode=10003&regType=ctab').text

        parts = re.findall(r"svr_cert\s*\+=\s*'([^']*)';", html_content)
        pem_data = "".join(parts).replace("\\n", "\n")

        pem_lines = pem_data.strip().splitlines()
        b64_data = ''.join([line for line in pem_lines if not line.startswith('-----')])
        
        return base64.b64decode(b64_data)
    
    def get_signed_hex(self) -> str:
        """
        PKCS#7 서명을 생성합니다.
        """

        data_to_sign = b'Hello GovKR!' # 실제로 서명시 사용한 원본 데이터(original_data)가 무엇인지는 검증하지 않습니다. 서명의 유효성이 중요!
        pkcs7_der = self.signer.pkcs7_signed_msg(data_to_sign)
        return pkcs7_der.hex()

    def login(self):
        """
        서명 데이터와 vid 메시지를 생성한 후 로그인을 시도합니다.
        """
        
        # PKCS#7 서명 생성
        signed_hex = self.get_signed_hex()

        # vid 메시지 생성 (개인키 고유값과 서버 인증서를 사용)
        vid_msg = self._generate_vid_msg(self.signer._rand_num.asOctets())

        data = {
            'a': '/nlogin/loginByIdPwd',
            'vidMsg': vid_msg,
            'xml': signed_hex,
            'pkcs1Msg': signed_hex,
            'currUrl': '',
            'randomnum': '',
            'loginType': 'browserLogin',
            'certiType': '',
            'certiType2': '',
            'browserYn': 'Y',
            'regYn': '',
            'isTouchYn': '',
            'loginGb': '',
            'loginFlag': '',
            'cdFlag': '',
            'dynaPathVer': 'N/A'
        }

        headers = {
            'Content-Type': 'application/x-www-form-urlencoded',
            'Referer': 'https://www.gov.kr/nlogin/?Mcode=10003&regType=ctab',
            'Origin': 'https://www.gov.kr',
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/119.0'
        }

        response = self.session.post(
            'https://www.gov.kr/nlogin/loginByIdPwd',
            data=urllib.parse.urlencode(data),
            headers=headers,
            allow_redirects=False
        )

        if response.status_code != 302:
            return False

        location = response.headers.get('location')

        if location != 'https://www.gov.kr/portal/main':
            raise LoginError(f"로그인 오류: 잘못된 리다이렉션 주소: {location}")

    def get_user_name(self) -> str:
        response = self.session.get('https://www.gov.kr/portal/main')

        for line in response.text.split('\n'):
            if 'var userNm =' in line:
                return line.strip()
            
        raise LoginError("로그인 오류: 사용자 이름을 추출하지 못했습니다.")


def main():
    # import getpass
    # password = getpass.getpass("인증서의 비밀번호를 입력하세요: ")
    
    password = input("인증서의 비밀번호를 입력하세요: ")

    client = Gov24_Client(
        sign_cert_path="./인증서/signCert.der",
        sign_pri_path="./인증서/signPri.key",
        sign_pri_password=password,
        encryption_cert_path="./인증서/svr_cert.der" # 미기입시 자동 수집
    )
    
    client.login()
    
    user_name = client.get_user_name()
    print(f"사용자 이름: {user_name}")


if __name__ == '__main__':
    main()