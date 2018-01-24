#include "PathUtils.h"
#include <shlwapi.h>

std::string PathUtils::GetModuleFolder()
{
	char szPath[MAX_PATH];
	char szBuffer[MAX_PATH];
	char * pszFile;

	::GetModuleFileName(NULL, (LPTCH)szPath, sizeof (szPath) / sizeof(*szPath));
	::GetFullPathName ((LPTSTR)szPath, sizeof (szBuffer) /  sizeof(*szBuffer), (LPTSTR)szBuffer, (LPTSTR*)&pszFile);
	*pszFile = 0;
	
	std::string ret = szBuffer;
	return ret;
}

bool PathUtils::FileExists(const std::string& fname)
{
	return PathFileExists(fname.c_str());
}
