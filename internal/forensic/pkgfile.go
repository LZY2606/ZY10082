package forensic

import "os"

func readPackageFile(svc *Service, pkgID string) ([]byte, error) {
	return os.ReadFile(svc.packageFilePath(pkgID))
}
