package osssanitizer.astgen_java.util;

public class SootConfigUtil {
	private String intype;
	private String sootOutDir;
	private String processDir;
	private String androidJarDir;
	private int threadCount;
	private boolean showStats;
	private boolean keepSootOutput;
	private boolean keepBBInfo;
	
	public String getIntype() {
		return intype;
	}
	public void setIntype(String intype) {
		this.intype = intype;
	}
	public String getSootOutDir() {
		return sootOutDir;
	}
	public void setSootOutDir(String sootOutDir) {
		this.sootOutDir = sootOutDir;
	}
	public String getProcessDir() {
		return processDir;
	}
	public void setProcessDir(String processDir) {
		this.processDir = processDir;
	}
	public String getAndroidJarDir() {
		return androidJarDir;
	}
	public void setAndroidJarDir(String androidJarDir) {
		this.androidJarDir = androidJarDir;
	}
	public int getThreadCount() {
		return threadCount;
	}
	public void setThreadCount(int threadCount) {
		this.threadCount = threadCount;
	}
	public boolean isShowStats() {
		return showStats;
	}
	public void setShowStats(boolean showStats) {
		this.showStats = showStats;
	}
	public boolean isKeepSootOutput() {
		return keepSootOutput;
	}
	public void setKeepSootOutput(boolean keepSootOutput) {
		this.keepSootOutput = keepSootOutput;
	}
	public boolean isKeepBBInfo() {
		return keepBBInfo;
	}
	public void setKeepBBInfo(boolean keepBBInfo) {
		this.keepBBInfo = keepBBInfo;
	}
}
