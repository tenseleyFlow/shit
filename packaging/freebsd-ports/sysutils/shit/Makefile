PORTNAME=	shit
DISTVERSIONPREFIX=	v
DISTVERSION=	0.1.0
CATEGORIES=	sysutils

MAINTAINER=	mfwolffe@outlook.com
COMMENT=	Magic undo for the command line
WWW=		https://github.com/tenseleyFlow/shit

LICENSE=	AGPLv3+
LICENSE_FILE=	${WRKSRC}/LICENSE

ONLY_FOR_ARCHS=	amd64 aarch64
ONLY_FOR_ARCHS_REASON=	only x86_64 and arm64 are tested

USES=		cargo
USE_GITHUB=	yes
GH_ACCOUNT=	tenseleyFlow
USE_RC_SUBR=	shit

# Binaries come from `cargo install` in USES=cargo. The workspace is not a
# single crate, so install each member and the preload shim by hand.
CARGO_INSTALL=	no
CARGO_BUILD_ARGS=	--workspace
SUB_FILES=	pkg-message

do-install:
	${INSTALL_PROGRAM} ${CARGO_TARGET_DIR}/release/shit ${STAGEDIR}${PREFIX}/bin
	${INSTALL_PROGRAM} ${CARGO_TARGET_DIR}/release/shitd ${STAGEDIR}${PREFIX}/bin
	${INSTALL_PROGRAM} ${CARGO_TARGET_DIR}/release/shit-helper ${STAGEDIR}${PREFIX}/bin
	${MKDIR} ${STAGEDIR}${PREFIX}/lib/shit
	${INSTALL_LIB} ${CARGO_TARGET_DIR}/release/libshit_preload_shim.so \
		${STAGEDIR}${PREFIX}/lib/shit
	${MKDIR} ${STAGEDIR}${DATADIR}/shell
	${INSTALL_DATA} ${WRKSRC}/LICENSE ${STAGEDIR}${DATADIR}
	${INSTALL_DATA} ${WRKSRC}/shell/* ${STAGEDIR}${DATADIR}/shell
	# Wrappers, package-manager hooks and descriptors.
	cd ${WRKSRC}/packaging && ${COPYTREE_SHARE} \
		"descriptors pkg-hooks cloud-hooks container-hooks db-hooks net-hooks proc-hooks svc-hooks" \
		${STAGEDIR}${DATADIR}
	${FIND} ${STAGEDIR}${DATADIR} -name '*-wrapper' -o -name '*.sh' | \
		${XARGS} ${CHMOD} 755

# CARGO_CRATES lives in Makefile.crates. Regenerate it per release with
# `make cargo-crates > Makefile.crates` inside a checkout of this port.
.include "${.CURDIR}/Makefile.crates"

.include <bsd.port.mk>
