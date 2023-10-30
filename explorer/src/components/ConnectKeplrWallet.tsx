import { useChain, useWallet, ChainProvider } from '@cosmos-kit/react';
import { Box, Button, Card } from '@mui/material';
import Big from 'big.js';

import { useEffect, useState, useMemo } from 'react';

export function useIsClient() {
  const [isClient, setIsClient] = useState(false);

  useEffect(() => {
    setIsClient(true);
  }, []);

  return isClient;
}

export const uNYMtoNYM = (unym: string, rounding = 6) => {
  const nym = Big(unym).div(1000000).toFixed(rounding);

  return {
    asString: () => {
      return nym;
    },
    asNumber: () => {
      return Number(nym);
    },
  };
};

export default function ConnectKeplrWallet() {
  const { username, connect, disconnect, wallet, openView, address, getCosmWasmClient } = useChain('nyx');
  const { status: globalStatus, mainWallet } = useWallet(); // status here is the global wallet status for all activated chains (chain is activated when call useChain)
  const isClient = useIsClient();

  useEffect(() => {
    const fn = async () => {
      await mainWallet?.connect();
    };
    fn();
  }, []);

  const [balance, setBalance] = useState<{
    status: 'loading' | 'success';
    data?: string;
  }>({ status: 'loading', data: undefined });

  useEffect(() => {
    const getBalance = async (walletAddress: string) => {
      setBalance({ status: 'loading', data: undefined });

      const account = await getCosmWasmClient();
      const uNYMBalance = await account.getBalance(walletAddress, 'unym');
      const NYMBalance = uNYMtoNYM(uNYMBalance.amount).asString();

      setBalance({ status: 'success', data: NYMBalance });
    };

    if (address) {
      getBalance(address);
    }
  }, [address, getCosmWasmClient]);

  console.log('balance :>> ', balance);

  if (!isClient) return null;

  const getGlobalbutton = () => {
    if (globalStatus === 'Connecting') {
      return <Button onClick={() => connect()}>{`Connecting ${wallet?.prettyName}`}</Button>;
    }
    if (globalStatus === 'Connected') {
      return (
        <Box display={'flex'} alignItems={'center'}>
          <Button onClick={() => openView()}>
            <div>
              <span>Connected to: {wallet?.prettyName}</span>
            </div>
          </Button>

          <Box>{address}</Box>
          <Box>Balance: {balance.data} NYM</Box>

          <Button
            onClick={async () => {
              await disconnect();
              // setGlobalStatus(WalletStatus.Disconnected);
            }}
          >
            Disconnect
          </Button>
        </Box>
      );
    }

    return <Button onClick={() => connect()}>Connect Wallet</Button>;
  };

  return (
    <Card className="min-w-[350px] max-w-[800px] mt-20 mx-auto p-10">
      <Box>
        <div className="flex justify-start space-x-5">{getGlobalbutton()}</div>
      </Box>
    </Card>
  );
}
