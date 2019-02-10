import sys
import zlib
from file_ext_analysis import *


class UnallocatedClustersCarving:
    def __init__(self, path):
        self.f = open(path, "rb")

        self.boot_sector = self.f.read(200)

        self.bytes_per_sector = int.from_bytes(self.boot_sector[11:13], byteorder='little')       # 11 - 12
        self.sector_per_cluster = int.from_bytes(self.boot_sector[13:14], byteorder='little')     # 13
        self.reserved_sector_count = int.from_bytes(self.boot_sector[14:16], byteorder='little')  # 14 - 15
        self.number_of_fats = int.from_bytes(self.boot_sector[16:17], byteorder='little')         # 16
        self.total_sectors_32 = int.from_bytes(self.boot_sector[32:36], byteorder='little')       # 32 - 35
        self.fat_size = int.from_bytes(self.boot_sector[36:40], byteorder='little')               # 36 - 39
        self.root_dir_cluster = int.from_bytes(self.boot_sector[44:48], byteorder='little')       # 44 - 47

        self.bytes_per_cluster = self.bytes_per_sector * self.sector_per_cluster  # 클러스트 한 개의 전체 Bytes

        self.fat_location = self.reserved_sector_count * self.bytes_per_sector  # FAT 영역의 시작 위치
        self.fat_size_bytes = self.fat_size * self.bytes_per_sector  # FAT 한 개의 전체 Bytes
        
        self.data_location = self. fat_location + self.fat_size * self.number_of_fats * self.bytes_per_sector  # Data 영역의 시작 위치
        self.total_clusters = int((self.total_sectors_32 - self.reserved_sector_count - (self.fat_size * self.number_of_fats)) / self.sector_per_cluster)  # Data 영역의 총 클러스터 수

        self.unallocated_clusters_list = []
        self.get_unallocated_clusters_list()

        self.n_cluster_location = None  # 카빙할 비할당된 클러스터 번호를 저장할 변수
        self.file_carving()  # 데이터 영역에서 비할당된 클러스터를 대상으로 파일 카빙
        # self.file_carving_all()
        self.f.close()

    def get_unallocated_clusters_list(self):
        self.f.seek(self.fat_location)  # FAT1 영역으로 이동
        fat1_entries = self.f.read((self.total_clusters + 2) * 4)  # FAT1 영역에서 데이터 영역의 클러스터 수 만큼 읽기

        is_unallocated_cluster = int.from_bytes(b'\xff\xff\xff\x0f', byteorder='little')  # 각 FAT 엔트리의 클러스터가 할당되지 않았는지 검사하기 위한 변수
        cluster_num = 2

        for i in range(8, (self.total_clusters + 2) * 4, 4):
            fat_entry = int.from_bytes(fat1_entries[i:i+4], byteorder='little')
            if (fat_entry & is_unallocated_cluster) == 0:
                self.unallocated_clusters_list.append(cluster_num)
            cluster_num += 1

    def file_carving(self):
        for i in range(len(self.unallocated_clusters_list)):
            self.n_cluster_location = self.data_location + ((self.unallocated_clusters_list[i] - 2) * self.bytes_per_cluster)  # 데이터 영역의 N 번째 클러스터
            self.f.seek(self.n_cluster_location)  # 데이터 영역의 N 번째 클러스터로 이동
            data = self.f.read(self.bytes_per_cluster)
            ext = get_file_ext(data)

            if ext == "zip":
                print("%d\t%s" % (self.unallocated_clusters_list[i], ext))
                self.analyze_zip(data)
            elif ext:
                print("%d\t%s" % (self.unallocated_clusters_list[i], ext))

    def file_carving_all(self):
        for i in range(2, int(self.fat_size_bytes / 4)):
            self.n_cluster_location = self.data_location + ((i-2) * self.bytes_per_cluster)
            self.f.seek(self.n_cluster_location)  # 데이터 영역의 N 번째 클러스터로 이동
            data = self.f.read(self.bytes_per_cluster)
            ext = get_file_ext(data)

            if ext == "zip":
                print("%d\t%s" % (i, ext))
                self.analyze_zip(data)
            elif ext:
                print("%d\t%s" % (i, ext))

    def analyze_zip(self, data):
        i = 0
        while (i + 30) < self.bytes_per_cluster:  # i+29 => 가변 값을 제외한 Local File Header의 길이
            if data[i:i + 4] == b'\x50\x4B\x03\x04':
                compression_method = int.from_bytes(data[i + 8:i + 10], byteorder='little')
                compressed_size = int.from_bytes(data[i + 18:i + 22], byteorder='little')
                file_name_length = int.from_bytes(data[i + 26:i + 28], byteorder='little')
                extra_field_length = int.from_bytes(data[i + 28:i + 30], byteorder='little')

                if (i + 30 + file_name_length) < self.bytes_per_cluster:  # 파일명이 한 클러스터 내에 있는지 확인
                    try:
                        file_name = data[i + 30:i + 30 + file_name_length].decode()  # 파일명이 UTF-8 인코딩일 경우
                    except UnicodeDecodeError:
                        file_name = data[i + 30:i + 30 + file_name_length].decode("EUC-KR")  # 파일명이 EUC-KR 인코딩일 경우
                    except:  # 파일명이 UTF-8, EUC-KR 인코딩이 아닐 경우
                        file_name = ""

                    if compressed_size > 0 and (i+30+file_name_length+extra_field_length+compressed_size) < self.bytes_per_cluster:  # 한 파일의 압축된 데이터가 있는지와 한 클러스터 내에 있는지 확인
                        compressed_data = data[i+30+file_name_length+extra_field_length:i+30+file_name_length+extra_field_length+compressed_size]  # 한 파일의 압축된 데이터

                        if compression_method == 8:  # Deflate 압축 방식을 사용하는지 확인
                            try:
                                decompressed_data = zlib.decompress(compressed_data, wbits=-zlib.MAX_WBITS)
                                ext = get_file_ext(decompressed_data)
                                if not ext:  # get_file_ext 함수에서 False를 반환 받았을 경우
                                    ext = ""
                            except zlib.error:
                                ext = ""

                        elif compression_method == 0:  # 압축하지 않을 때
                            decompressed_data = compressed_data
                            ext = get_file_ext(decompressed_data)
                            if not ext:
                                ext = ""

                        else:
                            ext = ""

                        print("\t%s %s" % (file_name, ext))

                    else:  # 한 파일의 압축된 데이터가 한 클러스터 내에 없을 때 파일명만 출력
                        print("\t%s" % file_name)

                    i += 30 + file_name_length + extra_field_length + compressed_size  # 다음 Local File Header로 이동

                else:
                    break

            else:  # 예외 상황 발생시
                i += 1


if __name__ == "__main__":
    if len(sys.argv) >= 2:
        UnallocatedClustersCarving(sys.argv[1])
    else:
        print("syntax: python fat32.py <path>")
