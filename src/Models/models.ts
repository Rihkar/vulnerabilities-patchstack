export type VulnerabilitesDataType = {
  id: string;
  title: string;
  truncatedDescription: string;
  overview: string;

  firstDescription: string;
  ulDescription: string[];
  lastDescription: string;

  firstPrevention: string;
  ulPrevention: string[];
  lastPrevention: string;
};
