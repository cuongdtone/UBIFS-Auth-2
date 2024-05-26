#ifndef EXVERI_H
#define EXVERI_H


unsigned char exveri_sign[] = {0x30, 0x82, 0x02, 0xa9, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x07, 0x02, 0xa0, 0x82, 0x02, 0x9a, 0x30, 
            0x82, 0x02, 0x96, 0x02, 0x01, 0x01, 0x31, 0x0f, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 
            0x01, 0x05, 0x00, 0x30, 0x0b, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x07, 0x01, 0x31, 0x82, 0x02, 0x71, 
            0x30, 0x82, 0x02, 0x6d, 0x02, 0x01, 0x01, 0x30, 0x46, 0x30, 0x2e, 0x31, 0x2c, 0x30, 0x2a, 0x06, 0x03, 0x55, 0x04, 0x03, 
            0x0c, 0x23, 0x42, 0x75, 0x69, 0x6c, 0x64, 0x20, 0x74, 0x69, 0x6d, 0x65, 0x20, 0x61, 0x75, 0x74, 0x6f, 0x67, 0x65, 0x6e, 
            0x65, 0x72, 0x61, 0x74, 0x65, 0x64, 0x20, 0x6b, 0x65, 0x72, 0x6e, 0x65, 0x6c, 0x20, 0x6b, 0x65, 0x79, 0x02, 0x14, 0x2d, 
            0x00, 0x29, 0xc7, 0x84, 0x28, 0xab, 0x92, 0xc1, 0x36, 0x6a, 0x3a, 0x5a, 0x3e, 0x3b, 0x2f, 0xaa, 0x74, 0xf1, 0x02, 0x30, 
            0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05, 0x00, 0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 
            0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01, 0x05, 0x00, 0x04, 0x82, 0x02, 0x00, 0x17, 0xf4, 0x82, 0x28, 0x0b, 0x3d, 0xd8, 
            0x4c, 0xa1, 0x2a, 0xce, 0xd9, 0xb7, 0x28, 0x6c, 0xbd, 0x24, 0xee, 0x33, 0xf4, 0x35, 0x65, 0x52, 0x9b, 0xf3, 0x47, 0x04, 
            0x53, 0xb9, 0xe7, 0x52, 0xd4, 0x8e, 0xcd, 0x25, 0x18, 0xaa, 0xc5, 0x2b, 0xc2, 0xfe, 0xae, 0xf7, 0x93, 0xf2, 0x4a, 0x6e, 
            0x99, 0x01, 0xef, 0x93, 0xd1, 0x83, 0xc3, 0xbf, 0x04, 0xc2, 0x34, 0xa2, 0x8c, 0xbd, 0x56, 0xdb, 0xc2, 0xf4, 0x94, 0x3a, 
            0x7a, 0x9e, 0x06, 0x92, 0xbf, 0x61, 0x61, 0x70, 0xd8, 0x4e, 0x03, 0xf1, 0x16, 0xa0, 0x9d, 0x54, 0x68, 0x06, 0x02, 0x8b, 
            0x96, 0xdf, 0xb0, 0x8e, 0x11, 0x9e, 0xc6, 0x26, 0xd2, 0x10, 0x1a, 0x78, 0x20, 0x69, 0xab, 0xe9, 0x17, 0x31, 0xba, 0x9b, 
            0xf4, 0xbe, 0xd1, 0xbb, 0x5e, 0xcd, 0x7a, 0x12, 0xb9, 0x31, 0x1b, 0x6c, 0x29, 0xbe, 0x12, 0xc8, 0xc7, 0xed, 0x3e, 0xd8, 
            0xa5, 0xa0, 0x57, 0xc0, 0x76, 0x78, 0x85, 0xb9, 0x87, 0xd6, 0xd2, 0xa7, 0x51, 0xb2, 0xc8, 0x49, 0xa0, 0xb5, 0x26, 0xa6, 
            0xf0, 0xb5, 0xf0, 0xb7, 0x90, 0x2e, 0x7d, 0x29, 0xad, 0x40, 0x35, 0x4e, 0x5d, 0x37, 0x25, 0x75, 0x54, 0x45, 0x07, 0x5f, 
            0xbb, 0x32, 0x44, 0x05, 0x5e, 0xf6, 0xe4, 0x04, 0xf9, 0xcc, 0x9c, 0x71, 0xc2, 0x62, 0x9f, 0x2e, 0xc6, 0x97, 0x08, 0xde, 
            0xf0, 0x16, 0x6e, 0x84, 0x97, 0xb6, 0xdc, 0x25, 0xdb, 0x9b, 0x6c, 0xf0, 0xe6, 0x84, 0x0b, 0x02, 0x68, 0x58, 0x60, 0xb3, 
            0x81, 0xd7, 0xb7, 0xe3, 0xa1, 0x25, 0x6d, 0x15, 0x12, 0x5b, 0x9e, 0x56, 0xd9, 0xba, 0x93, 0x63, 0x1a, 0x73, 0xd5, 0x5e, 
            0x18, 0xea, 0xaa, 0x70, 0xaa, 0x1e, 0x1e, 0x6c, 0x89, 0xb9, 0x14, 0xe4, 0x6c, 0x4c, 0xe0, 0x29, 0x84, 0x92, 0xac, 0x37, 
            0x7c, 0xa5, 0x3b, 0xe4, 0x46, 0x42, 0x42, 0xb1, 0xc0, 0x6c, 0x68, 0xfe, 0xfc, 0xb1, 0xc8, 0x89, 0x19, 0x25, 0x82, 0xb8, 
            0xd6, 0x82, 0x8a, 0x80, 0x8b, 0xb7, 0x84, 0x1d, 0x07, 0xa0, 0x42, 0x4b, 0x44, 0x1a, 0xeb, 0xee, 0x31, 0x34, 0x9d, 0x7a, 
            0x9f, 0x7f, 0x26, 0x9e, 0x20, 0xcf, 0x5d, 0x9d, 0xf2, 0x7a, 0x9f, 0xfb, 0xd6, 0x83, 0x7c, 0x3e, 0x2c, 0xc3, 0x73, 0x21, 
            0x85, 0x9b, 0x5e, 0x71, 0x51, 0x71, 0xf8, 0xf9, 0x93, 0x11, 0x21, 0x7e, 0x57, 0x64, 0x4b, 0x5b, 0xab, 0xd2, 0xfc, 0xbe, 
            0xcc, 0x73, 0x4f, 0x0e, 0x20, 0xe6, 0x74, 0x26, 0xc5, 0x9b, 0x0d, 0x1f, 0x23, 0x99, 0x56, 0x39, 0xa4, 0x33, 0xab, 0x40, 
            0xb6, 0x26, 0xbb, 0xdb, 0x1f, 0xde, 0x7b, 0x7c, 0x7c, 0x2d, 0x4e, 0xaa, 0x8d, 0xd8, 0x0c, 0x44, 0xe4, 0x02, 0x7b, 0x43, 
            0x0f, 0xaf, 0x10, 0x8e, 0x0c, 0x2c, 0x4d, 0xb0, 0x45, 0x25, 0x37, 0x1b, 0x51, 0xb9, 0x34, 0x6e, 0xce, 0xdc, 0x74, 0x4f, 
            0x9c, 0x32, 0xe3, 0xad, 0x43, 0xdb, 0xe5, 0x23, 0x88, 0x3b, 0x73, 0x2d, 0x92, 0xe3, 0x6e, 0x01, 0xd2, 0xf1, 0xa6, 0x2e, 
            0x10, 0x72, 0x29, 0x11, 0x1a, 0x1f, 0x64, 0xc7, 0xb0, 0x16, 0x1a, 0xd0, 0x1f, 0x7e, 0x28, 0xf3, 0xf7, 0xd9, 0x74, 0xec, 
            0xb2, 0xd1, 0x1e, 0x77, 0xcb, 0xc2, 0xeb, 0xdc, 0x5e, 0x1e, 0xc6, 0xf2, 0x1c, 0x4f, 0xf6, 0x2f, 0x67, 0x1d, 0x7e, 0xac, 
            0x1a, 0xad, 0x58, 0xeb, 0xb2, 0xec, 0x66, 0xc4, 0x2c, 0x31, 0x40, 0xc7, 0x68, 0xc9, 0x47, 0x7b, 0xa4, 0x0a, 0xd7, 0x7a, 
            0x41, 0x45, 0xa1, 0xb5, 0x9f, 0x66, 0x6b, 0x78, 0xaf, 0x08, 0x75, 0xb8, 0x4e, 0x13, 0x81, 0xbf, 0xe1, 0xed, 0xe1, 0x7b, 
            0x10, 0xb3, 0xa5, 0xb8, 0xb6, 0x67, 0x9f, 0x20, 0x04, 0xb3, 0x49, 0xa7, 0xa7, 0x0d, 0xe5, 0x64, 0xb3, 0xae, 0xa3, 0xbc, 
            0xcd, 0x5a, 0xc5, 0xf3, 0x7a};

unsigned char exveri_cert[] = {0x30, 0x82, 0x05, 0x28, 0x30, 0x82, 0x03, 0x10, 0xa0, 0x03, 0x02, 0x01, 0x02, 0x02, 0x14, 0x2d, 0x00, 0x29, 0xc7, 0x84, 
0x28, 0xab, 0x92, 0xc1, 0x36, 0x6a, 0x3a, 0x5a, 0x3e, 0x3b, 0x2f, 0xaa, 0x74, 0xf1, 0x02, 0x30, 0x0d, 0x06, 0x09, 0x2a, 
0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0d, 0x05, 0x00, 0x30, 0x2e, 0x31, 0x2c, 0x30, 0x2a, 0x06, 0x03, 0x55, 0x04, 
0x03, 0x0c, 0x23, 0x42, 0x75, 0x69, 0x6c, 0x64, 0x20, 0x74, 0x69, 0x6d, 0x65, 0x20, 0x61, 0x75, 0x74, 0x6f, 0x67, 0x65, 
0x6e, 0x65, 0x72, 0x61, 0x74, 0x65, 0x64, 0x20, 0x6b, 0x65, 0x72, 0x6e, 0x65, 0x6c, 0x20, 0x6b, 0x65, 0x79, 0x30, 0x20, 
0x17, 0x0d, 0x32, 0x34, 0x30, 0x35, 0x32, 0x35, 0x30, 0x32, 0x31, 0x39, 0x31, 0x30, 0x5a, 0x18, 0x0f, 0x32, 0x31, 0x32, 
0x34, 0x30, 0x35, 0x30, 0x31, 0x30, 0x32, 0x31, 0x39, 0x31, 0x30, 0x5a, 0x30, 0x2e, 0x31, 0x2c, 0x30, 0x2a, 0x06, 0x03, 
0x55, 0x04, 0x03, 0x0c, 0x23, 0x42, 0x75, 0x69, 0x6c, 0x64, 0x20, 0x74, 0x69, 0x6d, 0x65, 0x20, 0x61, 0x75, 0x74, 0x6f, 
0x67, 0x65, 0x6e, 0x65, 0x72, 0x61, 0x74, 0x65, 0x64, 0x20, 0x6b, 0x65, 0x72, 0x6e, 0x65, 0x6c, 0x20, 0x6b, 0x65, 0x79, 
0x30, 0x82, 0x02, 0x22, 0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01, 0x05, 0x00, 0x03, 
0x82, 0x02, 0x0f, 0x00, 0x30, 0x82, 0x02, 0x0a, 0x02, 0x82, 0x02, 0x01, 0x00, 0xf0, 0x02, 0x8a, 0xc7, 0x16, 0xc3, 0x85, 
0x88, 0x23, 0xaf, 0xc1, 0xc2, 0xd5, 0xad, 0x21, 0x81, 0x67, 0x31, 0x97, 0xfe, 0x02, 0x45, 0x9e, 0x72, 0x51, 0xea, 0x72, 
0x63, 0xa5, 0xb4, 0x74, 0xe6, 0x74, 0xe4, 0xfc, 0x08, 0xfa, 0xc6, 0xd0, 0xd0, 0xcf, 0x27, 0x74, 0xf4, 0x73, 0x5c, 0xb1, 
0x65, 0x57, 0xae, 0xb6, 0x9f, 0x2f, 0x07, 0x4e, 0x3c, 0xe3, 0x3a, 0x7c, 0xf0, 0xfc, 0x5e, 0xbb, 0x1d, 0x33, 0x42, 0xeb, 
0x53, 0xae, 0xd6, 0xa4, 0x00, 0x9a, 0xe5, 0x5b, 0x7e, 0x4f, 0x87, 0x4e, 0x02, 0x4d, 0x1a, 0x75, 0xee, 0xb1, 0x85, 0x09, 
0x41, 0x68, 0x5d, 0x77, 0x7d, 0x0b, 0x55, 0x8e, 0x06, 0x9b, 0x7d, 0x85, 0x13, 0x10, 0x3c, 0xd9, 0x1f, 0x1f, 0x5a, 0x91, 
0x9b, 0xec, 0x08, 0x47, 0x3e, 0xc2, 0x1e, 0x31, 0x04, 0x73, 0x11, 0xd8, 0x83, 0x38, 0x88, 0x35, 0x6d, 0x0b, 0x07, 0x1a, 
0x89, 0xdd, 0xcf, 0xb7, 0x81, 0x6b, 0x5c, 0x6e, 0xb5, 0x5f, 0xbf, 0xae, 0xd0, 0x3c, 0xb9, 0xd3, 0xa8, 0xec, 0xc7, 0x0f, 
0x09, 0x30, 0x8b, 0x0a, 0xd4, 0xcc, 0x2c, 0xf1, 0xbe, 0x1e, 0x36, 0x97, 0x59, 0xb3, 0xb5, 0x97, 0xad, 0xdc, 0x02, 0x6a, 
0x24, 0x37, 0x89, 0xe4, 0xfe, 0x6d, 0x31, 0xb3, 0x0f, 0xc2, 0xe1, 0x35, 0x8c, 0x57, 0xdd, 0xb3, 0xf8, 0xce, 0xc8, 0xc3, 
0xcc, 0x23, 0x90, 0xe7, 0x92, 0x90, 0x87, 0x27, 0x44, 0x98, 0xbb, 0x41, 0x72, 0xc1, 0xc7, 0x15, 0xce, 0x24, 0x45, 0xa1, 
0x4f, 0x36, 0x5e, 0xf6, 0x99, 0x73, 0x04, 0x32, 0x7f, 0xaa, 0x97, 0x51, 0xc8, 0x00, 0x85, 0x51, 0xbb, 0xe6, 0xcd, 0x59, 
0x52, 0xbe, 0x40, 0x7c, 0xcd, 0x22, 0xd7, 0x53, 0xd5, 0xe5, 0xad, 0x97, 0x2d, 0xb6, 0x40, 0x6a, 0x2a, 0xbd, 0xa5, 0x7b, 
0x51, 0x7f, 0xf6, 0xf9, 0x62, 0xee, 0x8c, 0x1c, 0xf5, 0x36, 0x5f, 0x20, 0x77, 0xc2, 0x22, 0x98, 0x18, 0x96, 0x04, 0x6c, 
0x8a, 0x2f, 0x96, 0x6e, 0x18, 0xc2, 0x94, 0x0e, 0x1a, 0x7d, 0x8c, 0xae, 0xbb, 0x78, 0x73, 0xb0, 0x7a, 0xa5, 0xc9, 0xb2, 
0x84, 0xc7, 0x1b, 0x24, 0x09, 0x38, 0x0f, 0x6b, 0xd5, 0xdb, 0xe9, 0x64, 0xe2, 0x72, 0xa7, 0x05, 0x60, 0x90, 0xc3, 0x72, 
0x5b, 0x3e, 0x4b, 0x87, 0x6e, 0x51, 0x76, 0xcd, 0x11, 0x94, 0x91, 0xec, 0xa7, 0x2c, 0xb5, 0xe4, 0xa7, 0x11, 0xaa, 0x8c, 
0x82, 0xb6, 0x43, 0x8b, 0x8c, 0x97, 0xe7, 0xaf, 0xf4, 0x45, 0x35, 0xf7, 0x1f, 0xfa, 0xe4, 0x48, 0x2d, 0xbc, 0x10, 0x04, 
0x5b, 0xb6, 0x36, 0x1c, 0x7d, 0xc0, 0x5b, 0xe3, 0xf4, 0x91, 0x6e, 0x6f, 0x85, 0xa1, 0xab, 0xd2, 0xf6, 0x0a, 0x38, 0x3a, 
0xbf, 0x86, 0xda, 0x0f, 0x76, 0x9a, 0x81, 0x5f, 0x56, 0x21, 0x6e, 0x5e, 0x63, 0x9f, 0x67, 0x69, 0x89, 0xd0, 0x34, 0x13, 
0x87, 0x8b, 0xd3, 0xc0, 0x24, 0x31, 0xc1, 0xff, 0xdb, 0x0f, 0x33, 0xc2, 0xed, 0x69, 0x72, 0xcc, 0xb3, 0x76, 0xc7, 0xf3, 
0x50, 0xc8, 0x14, 0xa3, 0x31, 0x5b, 0x8b, 0x7c, 0x36, 0x3a, 0x10, 0x96, 0x3d, 0xe5, 0xa3, 0xad, 0xf9, 0x77, 0x9c, 0xd1, 
0x32, 0xa1, 0x39, 0xd3, 0xcb, 0x60, 0x77, 0xd3, 0x55, 0xc0, 0x46, 0x88, 0x76, 0x78, 0xe8, 0x5b, 0xf8, 0x7e, 0x44, 0x91, 
0xa2, 0xc2, 0x08, 0x4a, 0xde, 0x45, 0xe7, 0x38, 0xdb, 0x92, 0x30, 0xb7, 0x34, 0x90, 0xb6, 0x02, 0x0f, 0x26, 0x4d, 0xc4, 
0x63, 0x52, 0x18, 0x6b, 0x07, 0x59, 0x4e, 0x05, 0x8d, 0xa4, 0xca, 0x64, 0x30, 0x7f, 0x0f, 0x1a, 0x62, 0x4d, 0x0f, 0x02, 
0x6b, 0x26, 0x74, 0x09, 0xf0, 0x49, 0x59, 0xd0, 0x9c, 0xcb, 0x97, 0x9f, 0xa3, 0x6e, 0x02, 0xf2, 0x09, 0x78, 0x8d, 0x14, 
0x4b, 0x70, 0xb8, 0xd1, 0x3d, 0x02, 0x03, 0x01, 0x00, 0x01, 0xa3, 0x3c, 0x30, 0x3a, 0x30, 0x0c, 0x06, 0x03, 0x55, 0x1d, 
0x13, 0x01, 0x01, 0xff, 0x04, 0x02, 0x30, 0x00, 0x30, 0x0b, 0x06, 0x03, 0x55, 0x1d, 0x0f, 0x04, 0x04, 0x03, 0x02, 0x07, 
0x80, 0x30, 0x1d, 0x06, 0x03, 0x55, 0x1d, 0x0e, 0x04, 0x16, 0x04, 0x14, 0xca, 0x03, 0x1c, 0xa5, 0x1b, 0x46, 0x3d, 0x34, 
0x4c, 0x8e, 0x48, 0x20, 0xf7, 0x66, 0x14, 0x55, 0x95, 0x22, 0xca, 0xce, 0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 
0xf7, 0x0d, 0x01, 0x01, 0x0d, 0x05, 0x00, 0x03, 0x82, 0x02, 0x01, 0x00, 0x53, 0xcb, 0xea, 0x93, 0xdc, 0xdc, 0xfe, 0x7d, 
0xca, 0x58, 0x00, 0x2c, 0x37, 0x2c, 0x82, 0x7d, 0x92, 0x9b, 0xd7, 0xb2, 0x53, 0x97, 0x8d, 0xc1, 0xd7, 0x8b, 0x44, 0x3e, 
0x93, 0xbe, 0x09, 0xf4, 0xad, 0xca, 0xd5, 0xfb, 0xe2, 0x98, 0x49, 0x2c, 0x0e, 0xd5, 0x60, 0xd3, 0x69, 0xa9, 0x0a, 0xd4, 
0xe7, 0xde, 0x5e, 0x04, 0xc5, 0x69, 0x59, 0x42, 0x14, 0xf7, 0x28, 0x90, 0xb6, 0x40, 0xdf, 0x95, 0x49, 0x8d, 0xf4, 0x53, 
0xac, 0xbf, 0x9d, 0x3c, 0xa8, 0x19, 0x1e, 0x14, 0xb4, 0xc5, 0x7b, 0x25, 0xb9, 0x81, 0xb6, 0x2f, 0x7e, 0x50, 0x25, 0x83, 
0x80, 0x04, 0xd7, 0x34, 0x0b, 0xd8, 0x18, 0x2b, 0x19, 0x6b, 0xe3, 0xaa, 0x03, 0x31, 0x78, 0x37, 0x61, 0x14, 0x95, 0xeb, 
0x8c, 0x74, 0xf9, 0xa9, 0x7e, 0x36, 0x59, 0x76, 0x94, 0x73, 0xed, 0x03, 0x48, 0x90, 0x28, 0x55, 0x0b, 0x4b, 0xb9, 0x7f, 
0xd7, 0x38, 0x17, 0x16, 0x42, 0x43, 0xd5, 0x45, 0x93, 0x5d, 0x7c, 0x57, 0x45, 0xab, 0xa0, 0x70, 0x12, 0x74, 0xf5, 0x26, 
0xcd, 0x01, 0xd3, 0xc4, 0x36, 0xa0, 0x50, 0xff, 0x78, 0x7d, 0x92, 0x70, 0xe7, 0x8a, 0x31, 0x0e, 0xef, 0x5d, 0xc7, 0x40, 
0xe9, 0x2f, 0x35, 0x20, 0xb5, 0x5e, 0x82, 0x0d, 0x89, 0xef, 0xfd, 0xfe, 0xfd, 0x03, 0xe9, 0x10, 0x50, 0xe5, 0xfe, 0x0b, 
0x72, 0xe7, 0xae, 0x81, 0x2c, 0x01, 0x3f, 0x6f, 0x86, 0x8d, 0x87, 0x65, 0x24, 0x34, 0x72, 0xf6, 0xeb, 0xee, 0x0e, 0x94, 
0xd0, 0xab, 0xf7, 0x7e, 0xb3, 0xd7, 0xdb, 0x02, 0xcc, 0x30, 0xcb, 0xcf, 0xe1, 0x2b, 0x97, 0x8e, 0xf6, 0xc7, 0xb8, 0x6d, 
0x7a, 0x06, 0xb7, 0x91, 0xbd, 0x06, 0xee, 0xd0, 0xc9, 0xcb, 0xf2, 0x68, 0x91, 0xe8, 0xd5, 0x9d, 0x5b, 0x8c, 0xa1, 0x96, 
0x19, 0xed, 0xd4, 0x89, 0x48, 0xbb, 0x8e, 0x73, 0x86, 0x63, 0xed, 0x98, 0xd0, 0x76, 0xf2, 0x23, 0xca, 0x17, 0xb8, 0x9c, 
0x4c, 0x94, 0x9f, 0xbd, 0xd5, 0x6d, 0xd7, 0xcb, 0x52, 0xbe, 0x0a, 0xa4, 0x6c, 0x57, 0x33, 0xfc, 0x45, 0x08, 0xc6, 0x00, 
0x43, 0x72, 0xd1, 0xbd, 0x58, 0x92, 0x42, 0x2f, 0x61, 0x27, 0x93, 0x9f, 0xc0, 0xab, 0x0a, 0xaf, 0xf2, 0xdd, 0x1f, 0xbd, 
0x3d, 0xa0, 0xd7, 0x75, 0x5b, 0x33, 0x46, 0xfa, 0xc0, 0x11, 0x08, 0xd2, 0x19, 0x1a, 0xa3, 0xed, 0xc9, 0x85, 0x87, 0x9d, 
0x2a, 0x3a, 0x2d, 0x24, 0x9e, 0xb7, 0xc1, 0x1a, 0x8a, 0x09, 0xc9, 0x91, 0xcd, 0xbe, 0x4b, 0xde, 0xb0, 0x69, 0xc2, 0x8f, 
0xb0, 0x2f, 0x51, 0xb6, 0xa6, 0xc0, 0x11, 0x94, 0x55, 0xdf, 0x1c, 0xa2, 0x67, 0x41, 0x8b, 0x6c, 0xf9, 0x56, 0xb6, 0xa4, 
0xb4, 0x86, 0x5d, 0xb5, 0x8e, 0x60, 0x46, 0x0a, 0x90, 0xd5, 0x4b, 0x91, 0x55, 0x48, 0xe2, 0x82, 0x47, 0xa5, 0xf9, 0x8e, 
0x11, 0xb1, 0xbd, 0xdd, 0xcf, 0x21, 0xa5, 0x80, 0x7d, 0xc0, 0x2a, 0xa8, 0xb7, 0x24, 0xcb, 0x53, 0x45, 0x67, 0x4b, 0x30, 
0x21, 0xd4, 0x10, 0x0a, 0x0b, 0x13, 0x1f, 0x10, 0x63, 0x94, 0xa6, 0xf6, 0xb5, 0x71, 0xdd, 0xe8, 0xaf, 0x32, 0x96, 0x55, 
0xf1, 0xb8, 0x02, 0x5d, 0xb0, 0x6f, 0xc5, 0xa0, 0x39, 0x38, 0xb9, 0xbc, 0x60, 0x66, 0x61, 0x69, 0x13, 0x1e, 0x45, 0x9d, 
0x2c, 0xf0, 0x58, 0x92, 0x06, 0xda, 0xe0, 0x6e, 0xd9, 0x64, 0x2c, 0xd7, 0x89, 0xeb, 0x7a, 0x6a, 0x4f, 0x7e, 0xbc, 0x61, 
0x7d, 0xa1, 0x08, 0x20, 0xb3, 0xbb, 0x6b, 0x0d, 0x63, 0x1f, 0xb3, 0x2d, 0x82, 0x42, 0x7d, 0x82, 0xbd, 0x3d, 0xe9, 0x77, 
0x47, 0x62, 0x49, 0x6a, 0x03, 0x6a, 0x72, 0x5b, 0xd1, 0xa4, 0x3d, 0xa2, 0x24, 0xed, 0x83, 0x37, 0xca, 0x59, 0x0b, 0xb3, 
0x4a, 0xa8, 0x85, 0xc0};


#endif /* EXVERI_H */