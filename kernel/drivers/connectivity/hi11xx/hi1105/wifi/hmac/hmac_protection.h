

#ifndef __HMAC_PROTECTION_H__
#define __HMAC_PROTECTION_H__

/* 1 ����ͷ�ļ����� */
#include "oal_ext_if.h"
#include "mac_vap.h"

#ifdef __cplusplus
#if __cplusplus
extern "C" {
#endif
#endif

#undef THIS_FILE_ID
#define THIS_FILE_ID OAM_FILE_ID_HMAC_PROTECTION_H
/* 2 �궨�� */
/* 3 ö�ٶ��� */
/* 4 ȫ�ֱ������� */
/* 5 ��Ϣͷ���� */
/* 6 ��Ϣ���� */
/* 7 STRUCT���� */
/* 8 UNION���� */
/* 9 OTHERS���� */
/* 10 �������� */
uint32_t hmac_protection_del_user(mac_vap_stru *pst_mac_vap, mac_user_stru *pst_mac_user);
uint32_t hmac_user_protection_sync_data(mac_vap_stru *pst_mac_vap);

#ifdef __cplusplus
#if __cplusplus
}
#endif
#endif

#endif /* end of hmac_protection.h */