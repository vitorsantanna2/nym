import * as React from 'react';
import { useTheme } from '@mui/material/styles';

export const TokenSVG: FCWithChildren = () => {
  const theme = useTheme();
  const color = theme.palette.text.primary;

  return (
    <svg xmlns="http://www.w3.org/2000/svg" width="24" height="25" viewBox="0 0 24 25" fill="none">
      <g clip-path="url(#clip0_2549_7563)">
        <path
          d="M20.4841 4.01607C15.8041 -0.67593 8.19607 -0.67593 3.51607 4.01607C-1.17593 8.70807 -1.17593 16.3041 3.51607 20.9841C8.20807 25.6761 15.8041 25.6761 20.4841 20.9841C25.1761 16.3041 25.1761 8.69607 20.4841 4.01607ZM19.4521 19.9521C15.3361 24.0681 8.65207 24.0681 4.53607 19.9521C0.42007 15.8361 0.42007 9.15207 4.53607 5.03607C8.65207 0.92007 15.3361 0.92007 19.4521 5.03607C23.5801 9.16407 23.5801 15.8361 19.4521 19.9521Z"
          fill="white"
        />
        <path
          d="M18.48 19.4965V5.50447C17.868 4.92847 17.184 4.42447 16.452 4.02847V17.4085L7.62002 3.98047C6.85202 4.38847 6.14402 4.89247 5.52002 5.49247V19.4965C6.13202 20.0725 6.81602 20.5765 7.54802 20.9725V7.59247L16.38 21.0205C17.148 20.6125 17.856 20.0965 18.48 19.4965Z"
          fill="white"
        />
      </g>
      <defs>
        <clipPath id="clip0_2549_7563">
          <rect width="24" height="24" fill="white" transform="translate(0 0.5)" />
        </clipPath>
      </defs>
    </svg>
  );
};
